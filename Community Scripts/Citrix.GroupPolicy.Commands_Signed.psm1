# Copyright (c) 2010 - 2014 Citrix Systems, Inc. All rights reserved.
# 
# Version   Date            Details
# 7.1       01.21.14        Fixes LA5474 ('Enabled' type change) and LA5584 (AccessControl Filter Import)

$snapin = "Citrix.Common.GroupPolicy"
if (!(Get-PSSnapin $snapin -ea 0))
{
    Write-Host "Loading $snapin..." -ForegroundColor Yellow
    Add-PSSnapin $snapin -ea Stop
}

##########################

<#
    .SYNOPSIS
        Exports group policies to XML files.
    .DESCRIPTION
        This cmdlet exports group policies from a Citrix farm into XML files in the specified folder.
    .PARAMETER  FolderPath
        The folder path where the files will be created.
    .PARAMETER  PolicyName
        The policy name.
    .PARAMETER  Type
        The policy type. Allowed values are User and Computer.
    .PARAMETER  DriveName
        An optional drive name. Defaults to LocalFarmGpo.
    .EXAMPLE
        PS C:\> Export-CtxGroupPolicy c:\policies
        This command exports all the group policies in the farm using the LocalFarmGpo drive.
    .EXAMPLE
        PS C:\> Export-CtxGroupPolicy c:\policies pol* user
        This command exports the user policies whose names match pol*.
    .INPUTS
        String.
    .OUTPUTS
        Policy object.
    .NOTES
        Multiple files are created in the specified folder.
    .LINK
        Import-CtxGroupPolicy
#>
Function Export-CtxGroupPolicy
{
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true)]
        [string] $FolderPath,
        [Parameter(Position=1, ValueFromPipelineByPropertyName=$true)]
        [string[]] $PolicyName = "*",
        [Parameter(Position=2, ValueFromPipelineByPropertyName=$true)]
        [string] [ValidateSet("Computer", "User")] $Type,
        [Parameter()]
        [string] $DriveName = "LocalFarmGpo"
    )

    process
    {
        if (!(Test-Path $FolderPath))
        {
            $dir = New-Item $FolderPath -Type Directory -Force -ErrorAction Stop
        }

        $pols = Get-CtxGroupPolicy $PolicyName $Type -DriveName $DriveName
        $configs = $pols | Get-CtxGroupPolicyConfiguration -DriveName $DriveName
        $filters = $pols | Get-CtxGroupPolicyFilter -DriveName $DriveName

        $pols | Export-CliXml "$FolderPath\GroupPolicy.xml"
        $configs | Export-CliXml "$FolderPath\GroupPolicyConfiguration.xml"
        $filters | Export-CliXml "$FolderPath\GroupPolicyFilter.xml"
    }
}

<#
    .SYNOPSIS
        Imports group policies from XML files.
    .DESCRIPTION
        This cmdlet imports group policies to Citrix farm using the XML files in the specified folder.
    .PARAMETER  FolderPath
        The folder path where the files are located.
    .PARAMETER  PolicyName
        The policy name.
    .PARAMETER  Type
        The policy type. Allowed values are User and Computer.
    .PARAMETER  DriveName
        An optional drive name. Defaults to LocalFarmGpo.
    .EXAMPLE
        PS C:\> Import-CtxGroupPolicy c:\policies
        This command imports the group policies from the specified folder using the LocalFarmGpo drive.
    .EXAMPLE
        PS C:\> Import-CtxGroupPolicy c:\policies pol* user
        This command imports the user policies whose names match pol*.
    .INPUTS
        String.
    .OUTPUTS
        Policy object.
    .NOTES
        If the group policies already exist, only the necessary updates will be performed.
    .LINK
        Export-CtxGroupPolicy
#>
Function Import-CtxGroupPolicy
{
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true)]
        [string] $FolderPath,
        [Parameter(Position=1, ValueFromPipelineByPropertyName=$true)]
        [string[]] $PolicyName = "*",
        [Parameter(Position=2, ValueFromPipelineByPropertyName=$true)]
        [string] [ValidateSet("Computer", "User")] $Type,
        [Parameter()]
        [string] $DriveName = "LocalFarmGpo"
    )

    process
    {
        $types = if (!$Type) { @("Computer", "User") } else { @($Type) }
        if (!(Test-Path $FolderPath)) { throw "Invalid folder path" }

        $pols = Import-CliXml "$FolderPath\GroupPolicy.xml" -ErrorAction Stop
        $configs = Import-CliXml "$FolderPath\GroupPolicyConfiguration.xml" -ErrorAction Stop
        $filters = Import-CliXml "$FolderPath\GroupPolicyFilter.xml" -ErrorAction Stop

        foreach( $pol in @($pols | Where { (FilterString $_.PolicyName $PolicyName) -and (FilterString $_.Type $types) } ))
        {
            Write-Verbose "Importing $($pol.PolicyName) $($pol.Type)"
            if ($pol | Get-CtxGroupPolicy -DriveName $DriveName -ea 0)
            {
                Write-Verbose "Updating existing policy $($pol.PolicyName)"
                $pol | Set-CtxGroupPolicy -DriveName $DriveName
            }
            else
            {
                Write-Verbose "Creating new policy $($pol.PolicyName)"
                $pol | New-CtxGroupPolicy -DriveName $DriveName
            }

            $configs | Where { ($_.PolicyName -eq $pol.PolicyName) -and ($_.Type -eq $pol.Type ) } |
                Set-CtxGroupPolicyConfiguration -DriveName $DriveName

            foreach( $filter in @($filters | Where { (FilterString $_.PolicyName $pol.PolicyName) -and (FilterString $_.Type $pol.Type) }))
            {
                if ($filter | Get-CtxGroupPolicyFilter -DriveName $DriveName -ea 0)
                {
                    Write-Verbose "Updating existing filter $($filter.FilterName)"
                    $filter | Set-CtxGroupPolicyFilter -DriveName $DriveName
                }
                else
                {
                    Write-Verbose "Creating new filter $($filter.FilterName)"
                    $filter | Add-CtxGroupPolicyFilter -DriveName $DriveName
                }
            }
        }
    }
}

<#
    .SYNOPSIS
        Gets group policies.
    .DESCRIPTION
        This cmdlet gets group policies using the Citrix.Common.GroupPolicy provider.
    .PARAMETER  PolicyName
        The policy name.
    .PARAMETER  Type
        The policy type. Allowed values are User and Computer.
    .PARAMETER  DriveName
        An optional drive name. Defaults to LocalFarmGpo.
    .EXAMPLE
        PS C:\> Get-CtxGroupPolicy
        This command gets all the group policies using the LocalFarmGpo drive.
    .EXAMPLE
        PS C:\> Get-CtxGroupPolicy pol*
        This command gets the policies of all types whose names match pol*.
    .INPUTS
        String.
    .OUTPUTS
        Policy object.
    .NOTES
    .LINK
        Set-CtxGroupPolicy
#>
Function Get-CtxGroupPolicy
{
    [CmdletBinding()]
    param(
        [Parameter(Position=0, ValueFromPipelineByPropertyName=$true)]
        [string[]] $PolicyName = "*",
        [Parameter(Position=1, ValueFromPipelineByPropertyName=$true)]
        [string] [ValidateSet("Computer", "User", $null)] $Type,
        [Parameter()]
        [string] $DriveName = "LocalFarmGpo"
    )

    process
    {
        $types = if (!$Type) { @("Computer", "User") } else { @($Type) }
        foreach($polType in $types)
        {
            $pols = @(Get-ChildItem "$($DriveName):\$polType" | Where-Object { FilterString $_.Name $PolicyName })
            foreach ($pol in $pols)
            {
               $props = CreateDictionary
               $props.PolicyName = $pol.Name
               $props.Type = $poltype
               $props.Description = $pol.Description
               $props.Enabled = $pol.Enabled
               $props.Priority = $pol.Priority
               CreateObject $props $pol.Name
            }
        }
    }
}

<#
    .SYNOPSIS
        Gets group policy configurations.
    .DESCRIPTION
        This cmdlet gets group policy configurations using the Citrix.Common.GroupPolicy provider.
    .PARAMETER  PolicyName
        The policy name.
    .PARAMETER  Type
        The policy type. Allowed values are User and Computer.
    .PARAMETER  ConfiguredOnly
        List only the configured settings.
    .PARAMETER  DriveName
        An optional drive name. Defaults to LocalFarmGpo.
    .EXAMPLE
        PS C:\> Get-CtxGroupPolicyConfiguration pol1 user
        This command gets the configuration of the user policy pol1.
    .EXAMPLE
        PS C:\> Get-CtxGroupPolicyConfiguration pol* -ConfiguredOnly
        This command gets the active policy configurations of policies of all types whose names match pol*.
    .INPUTS
        String.
    .OUTPUTS
        Policy object.
    .NOTES
    .LINK
        Set-CtxGroupPolicyConfiguration
#>
Function Get-CtxGroupPolicyConfiguration
{
    [CmdletBinding()]
    param(
        [Parameter(Position=0, ValueFromPipelineByPropertyName=$true)]
        [String[]] $PolicyName = "*",
        [Parameter(Position=1, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("Computer", "User", $null)] [String] $Type,
        [Parameter()]
        [Switch] $ConfiguredOnly,
        [Parameter()]
        [string] $DriveName = "LocalFarmGpo"
    )

    process
    {
        $types = if (!$Type) { @("Computer", "User") } else { @($Type) }
        foreach ($poltype in $types)
        {
            $pols = @(Get-ChildItem "$($DriveName):\$poltype" | Where-Object { FilterString $_.Name $PolicyName })
            foreach ($pol in $pols)
            {
                $props = CreateDictionary
                $props.PolicyName = $pol.Name
                $props.Type = $poltype

                foreach ($setting in @(Get-ChildItem "$($DriveName):\$poltype\$($pol.Name)\Settings" -Recurse |
                    Where-Object { $_.State -ne $null }))
                {
                    if (!$ConfiguredOnly -or $setting.State -ne "NotConfigured")
                    {
                        $setname = $setting.PSChildName
                        $config = CreateDictionary
                        $config.State = $setting.State.ToString()
                        if ($setting.Values -ne $null) { $config.Values = ([array]($setting.Values)) }
                        if ($setting.Value -ne $null) { $config.Value = ([string]($setting.Value)) }
                        $config.Path = $setting.PSPath.Substring($setting.PSPath.IndexOf("\Settings\")+10)
                        $props.$setname = CreateObject $config
                    }
                }
                CreateObject $props $pol.Name
            }
        }
    }
}

<#
    .SYNOPSIS
        Gets group policy filters.
    .DESCRIPTION
        This cmdlet gets group policy filters using the Citrix.Common.GroupPolicy provider.
    .PARAMETER  PolicyName
        The policy name.
    .PARAMETER  Type
        The policy type. Allowed values are User and Computer.
    .PARAMETER  FilterName
        The policy filter name.
    .PARAMETER  FilterType
        The policy filter type.
    .PARAMETER  DriveName
        An optional drive name. Defaults to LocalFarmGpo.
    .EXAMPLE
        PS C:\> Get-CtxGroupPolicyFilter
        This command gets all the group policy filters using the LocalFarmGpo drive.
    .EXAMPLE
        PS C:\> Get-CtxGroupPolicyFilter pol1 user
        This command gets the policy filters of the user policy pol1.
    .INPUTS
        String.
    .OUTPUTS
        Policy object.
    .NOTES
    .LINK
        Set-CtxGroupPolicyFilter
        Add-CtxGroupPolicyFilter
        Remove-CtxGroupPolicyFilter
#>
Function Get-CtxGroupPolicyFilter
{
    [CmdletBinding()]
    param(
        [Parameter(Position=0, ValueFromPipelineByPropertyName=$true)]
        [String[]] $PolicyName = "*",
        [Parameter(Position=1, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("Computer", "User", $null)] [String] $Type,
        [Parameter(Position=2, ValueFromPipelineByPropertyName=$true)]
        [String[]] $FilterName = "*",
        [Parameter(Position=3, ValueFromPipelineByPropertyName=$true)]
        [string] $FilterType = "*",
        [Parameter()]
        [string] $DriveName = "LocalFarmGpo"
    )

    process
    {
        $types = if (!$Type) { @("Computer", "User") } else { @($Type) }
        foreach ($poltype in $types)
        {
            $pols = @(Get-ChildItem "$($DriveName):\$poltype" | Where-Object { ($_.Name -ne "Unfiltered") -and (FilterString $_.Name $PolicyName) })
            foreach ($pol in $pols)
            {
                foreach ($filter in @(Get-ChildItem "$($DriveName):\$poltype\$($pol.Name)\Filters" -Recurse |
                    Where-Object { ($_.FilterType -ne $null) -and (FilterString $_.Name $FilterName) -and (FilterString $_.FilterType $FilterType)}))
                {
                    $props = CreateDictionary
                    $props.PolicyName = $pol.Name
                    $props.Type = $poltype
                    $props.FilterName = $filter.Name
                    $props.FilterType = $filter.FilterType
                    $props.Enabled = $filter.Enabled
                    $props.Mode = [string]($filter.Mode)
                    $props.FilterValue = $filter.FilterValue
                    if($filter.FilterType -eq "AccessControl")
                    {
                        $props.ConnectionType = $filter.ConnectionType
                        $props.AccessGatewayFarm = $filter.AccessGatewayFarm
                        $props.AccessCondition = $filter.AccessCondition
                    }
                    CreateObject $props $filter.Name
                }
            }
        }
    }
}

<#
    .SYNOPSIS
        Creates group policies.
    .DESCRIPTION
        This cmdlet creates group policies using the Citrix.Common.GroupPolicy provider.
    .PARAMETER  PolicyName
        The policy name.
    .PARAMETER  Type
        The policy type. Allowed values are User and Computer.
    .PARAMETER  Description
        The policy description.
    .PARAMETER  Enabled
        The enabled status.
    .PARAMETER  Priority
        The priority.
    .PARAMETER  DriveName
        An optional drive name. Defaults to LocalFarmGpo.
    .EXAMPLE
        PS C:\> New-CtxGroupPolicy pol1 user
        This command creates a user policy named pol1.
    .INPUTS
        String.
    .OUTPUTS
        Policy object.
    .NOTES
    .LINK
        Set-CtxGroupPolicy
        Remove-CtxGroupPolicy
#>
Function New-CtxGroupPolicy
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Position = 0, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [String] $PolicyName,
        [Parameter(Position = 1, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [String] [ValidateSet("Computer", "User")] $Type,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [String] $Description,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [Boolean] $Enabled,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [Int] $Priority,
        [Parameter()]
        [string] $DriveName = "LocalFarmGpo"
    )

    process
    {
        $params = $PSCmdlet.MyInvocation.BoundParameters
        if ($PsCmdlet.ShouldProcess($PolicyName))
        {
            $item = New-Item "$($DriveName):\$Type\$PolicyName"
            foreach ($prop in "Description", "Enabled", "Priority")
            {
                if ($params.ContainsKey($prop)) { Set-ItemProperty "$($DriveName):\$Type\$PolicyName" $prop $params.$prop }
            }
            Get-CtxGroupPolicy $PolicyName $Type -DriveName $DriveName
        }
    }
}

<#
    .SYNOPSIS
        Sets group policies.
    .DESCRIPTION
        This cmdlet sets group policy properties using the Citrix.Common.GroupPolicy provider.
    .PARAMETER  PolicyName
        The policy name.
    .PARAMETER  Type
        The policy type. Allowed values are User and Computer.
    .PARAMETER  Description
        The policy description.
    .PARAMETER  Enabled
        The enabled status.
    .PARAMETER  Priority
        The priority.
    .PARAMETER  DriveName
        An optional drive name. Defaults to LocalFarmGpo.
    .PARAMETER  Passthru
        To output the object processed.
    .EXAMPLE
        PS C:\> Set-CtxGroupPolicy pol1 user -Description test
        This command sets the description of the user policy pol1.
    .INPUTS
        String.
    .OUTPUTS
        Policy object.
    .NOTES
    .LINK
        New-CtxGroupPolicy
        Remove-CtxGroupPolicy
#>
Function Set-CtxGroupPolicy
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [String[]] $PolicyName,
        [Parameter(Position=1, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [String] [ValidateSet("Computer", "User")] $Type,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [String] $Description,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [Boolean] $Enabled,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [Int] $Priority,
        [Parameter()]
        [string] $DriveName = "LocalFarmGpo",
        [Parameter()]
        [Switch] $Passthru
    )

    process
    {
        $params = $PSCmdlet.MyInvocation.BoundParameters
        $pols = Get-CtxGroupPolicy $PolicyName $Type -DriveName $DriveName

        foreach ($pol in $pols)
        {
            if ($PsCmdlet.ShouldProcess($pol.PolicyName))
            {
                foreach ($prop in "Description", "Enabled", "Priority")
                {
                    if ($params.ContainsKey($prop) -and ($pol.$prop -ne $params.$prop))
                    {
                        Write-Verbose ("Setting {0} to {1}" -f $prop, $params.$prop)
                        Set-ItemProperty "$($DriveName):\$Type\$($pol.PolicyName)" $prop $params.$prop
                    }
                }
                if ($Passthru) { Get-CtxGroupPolicy $($pol.PolicyName) -Type $Type -DriveName $DriveName }
            }
        }
    }
}

<#
    .SYNOPSIS
        Removes group policies.
    .DESCRIPTION
        This cmdlet removes group policy properties using the Citrix.Common.GroupPolicy provider.
    .PARAMETER  PolicyName
        The policy name.
    .PARAMETER  Type
        The policy type. Allowed values are User and Computer.
    .PARAMETER  DriveName
        An optional drive name. Defaults to LocalFarmGpo.
    .PARAMETER  Passthru
        To output the object processed.
    .EXAMPLE
        PS C:\> Remove-CtxGroupPolicy pol1 user
        This command removes the user policy pol1.
    .INPUTS
        String.
    .OUTPUTS
        Policy object.
    .NOTES
    .LINK
        New-CtxGroupPolicy
        Set-CtxGroupPolicy
#>
Function Remove-CtxGroupPolicy
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [String[]] $PolicyName,
        [Parameter(Position=1, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [String] [ValidateSet("Computer", "User")] $Type,
        [Parameter()]
        [string] $DriveName = "LocalFarmGpo",
        [Parameter()]
        [Switch] $Passthru
    )

    process
    {
        $pols = @(Get-CtxGroupPolicy $PolicyName $Type -DriveName $DriveName)
        foreach ($pol in $pols)
        {
            if ($PSCmdlet.ShouldProcess($pol.PolicyName))
            {
                Remove-Item "$($DriveName):\$Type\$($pol.PolicyName)" -Recurse -Force
                if ($Passthru) { $pol }
            }
        }
    }
}

<#
    .SYNOPSIS
        Sets group policy configurations.
    .DESCRIPTION
        This cmdlet sets group policy configurations using the Citrix.Common.GroupPolicy provider.
    .PARAMETER  PolicyName
        The policy name.
    .PARAMETER  Type
        The policy type. Allowed values are User and Computer.
    .PARAMETER  Setting
        The setting name.
    .PARAMETER  State
        The setting state. Allowed values are Enabled, Disabled, NotConfigured, Allowed, Prohibited and UseDefault
    .PARAMETER  Value
        The setting value.
    .PARAMETER  InputObject
        The policy configuration object to update.
    .PARAMETER  DriveName
        An optional drive name. Defaults to LocalFarmGpo.
    .PARAMETER  Passthru
        To output the object processed.
    .EXAMPLE
        PS C:\> SGet-CtxGroupPolicyConfiguration user1 user AllowSpeedFlash Enabled
        This command enables the speed flash configuration for the user policy user1.
    .EXAMPLE
        PS C:\> $obj = Get-CtxGroupPolicyConfiguration user1 user
        PS C:\> $obj.AllowSpeedFlash.State = "Enabled"
        PS C:\> Set-CtxGroupPolicyConfiguration $obj
        This command enables the speed flash configuration for the user policy user1.
    .INPUTS
        Object.
    .OUTPUTS
        Policy object.
    .NOTES
    .LINK
        Get-CtxGroupPolicyConfiguration
#>
function Set-CtxGroupPolicyConfiguration
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(ParameterSetName = "Config", Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [String[]] $PolicyName,
        [Parameter(ParameterSetName = "Config", Position=1, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [String] [ValidateSet("Computer", "User")] $Type,
        [Parameter(ParameterSetName = "Config", Position=2, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string] $ConfigurationName,
        [Parameter(ParameterSetName = "Config", Position=3, ValueFromPipelineByPropertyName=$true)]
        [string] [ValidateSet("Enabled", "Disabled", "NotConfigured", "Allowed", "Prohibited", "UseDefault")] $State,
        [Parameter(ParameterSetName = "Config", Position=4, ValueFromPipelineByPropertyName=$true)]
        [string] $Value,
        [Parameter(ParameterSetName = "Object", Position=0, Mandatory=$true, ValueFromPipeline=$true)]
        [PSObject] $InputObject,
        [Parameter()]
        [string] $DriveName = "LocalFarmGpo",
        [Parameter()]
        [Switch] $Passthru
    )

    process
    {
        Write-Verbose "ParameterSetName=$($PSCmdlet.ParameterSetName)"
        if ($PSCmdlet.ParameterSetName -eq "Object")
        {
            $obj = $InputObject
            $PolicyName = $obj.PolicyName
            $poltype = $obj.Type

            if ($PsCmdlet.ShouldProcess($PolicyName))
            {
                $current = $obj | Get-CtxGroupPolicyconfiguration -DriveName $DriveName
                if ($current -eq $null) { throw "Policy not found" }

                $ConfigurationObject = CompareObject $obj $current
                if ($ConfigurationObject -ne $null)
                {
                    foreach ($prop in @($ConfigurationObject | Get-Member -Type Properties | Select -Expand Name))
                    {
                        Write-Verbose "Processing setting $prop"
                        $config = $ConfigurationObject.$prop
                        $path = $config.Path
                        $state = $config.State.ToString()
                        if ($state -ne "NotConfigured")
                        {
                            if ($config.Values -ne $null)
                                { Set-ItemProperty "$($DriveName):\$poltype\$PolicyName\Settings\$path" Values ([object[]]($config.Values)) }
                            if ($config.Value -ne $null)
                                { Set-ItemProperty "$($DriveName):\$poltype\$PolicyName\Settings\$path" Value ([string]($config.Value)) }
                        }
                        Set-ItemProperty "$($DriveName):\$poltype\$PolicyName\Settings\$path" State $state
                    }
                }
                if ($Passthru) { $obj | Get-CtxGroupPolicyConfiguration -ConfiguredOnly -DriveName $DriveName }
            }
        }
        else
        {
            if ($PsCmdlet.ShouldProcess($PolicyName))
            {
                $pol = Get-CtxGroupPolicy $PolicyName $Type -EA Stop
                $setting = Get-ChildItem "$($DriveName):\$Type\unfiltered\Settings" -Recurse | Where { ($_.State -ne $null) -and ($_.PSChildName -eq $ConfigurationName) }
                if ($setting -eq $null)
                {
                    throw "Invalid configuration name"
                }
                $path = $setting.PSPath.Substring($setting.PSPath.IndexOf("\Settings\")+10)
                if ($State)
                    { Set-ItemProperty "$($DriveName):\$Type\$PolicyName\Settings\$path" State $state }
                if ($Value)
                    { Set-ItemProperty "$($DriveName):\$Type\$PolicyName\Settings\$path" Value $value }
                if ($Passthru) { Get-CtxGroupPolicyConfiguration $PolicyName $Type -ConfiguredOnly -DriveName $DriveName }
            }
        }
    }
}

<#
    .SYNOPSIS
        Sets group policy filters.
    .DESCRIPTION
        This cmdlet sets group policy filters using the Citrix.Common.GroupPolicy provider.
    .PARAMETER  PolicyName
        The policy name.
    .PARAMETER  Type
        The policy type. Allowed values are User and Computer.
    .PARAMETER  FilterName
        The policy filter name.
    .PARAMETER  FilterType
        The policy filter type.
    .PARAMETER  FilterValue
        The policy filter value.
    .PARAMETER  Enabled
        The enabled state.
    .PARAMETER  Mode
        The policy filter mode. Allowed values are Allow and Deny.
    .PARAMETER  DriveName
        An optional drive name. Defaults to LocalFarmGpo.
    .EXAMPLE
        PS C:\> Set-CtxGroupPolicyFilter pol1 user filter1 workergroup wg1
        This command sets the worker group filter filter1 to wg1 for user policy pol1.
    .INPUTS
        String.
    .OUTPUTS
        Policy object.
    .NOTES
    .LINK
        Get-CtxGroupPolicyFilter
        Add-CtxGroupPolicyFilter
        Remove-CtxGroupPolicyFilter
#>
Function Set-CtxGroupPolicyFilter
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string] $PolicyName,
        [Parameter(Position=1, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [String] [ValidateSet("Computer", "User")] $Type,
        [Parameter(Position=2, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string] $FilterName,
        [Parameter(Position=3, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string] $FilterType,
        [Parameter(Position=4, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string] $FilterValue,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string] $Enabled,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string] [ValidateSet("Allow", "Deny")] $Mode,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string] $AccessGatewayFarm,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string] $AccessCondition,
        [Parameter()]
        [string] $DriveName = "LocalFarmGpo",
        [Parameter()]
        [Switch] $Passthru
    )

    process
    {
        $params = $PSCmdlet.MyInvocation.BoundParameters
        $filters = Get-CtxGroupPolicyFilter $PolicyName $Type $FilterName $FilterType -DriveName $DriveName -ErrorAction Stop

        foreach($filter in $filters)
        {
            if ($PsCmdlet.ShouldProcess($filter.FilterName))
            {
                if ($FilterType -eq "AccessControl")
                {
                    foreach ($prop in  "Enabled", "Mode", "AccessGatewayFarm", "AccessCondition" )
                    {
                        if ($params.ContainsKey($prop) -and ($filter.$prop -ne $params.$prop))
                        {
                                Set-ItemProperty "$($DriveName):\$Type\$PolicyName\Filters\$FilterType\$FilterName" $prop $params.$prop
                        }
                    }
                }
                else
                {
                    foreach ($prop in  "Enabled", "Mode", "FilterValue" )
                    {
                        if ($params.ContainsKey($prop) -and ($filter.$prop -ne $params.$prop))
                        {
                                Set-ItemProperty "$($DriveName):\$Type\$PolicyName\Filters\$FilterType\$FilterName" $prop $params.$prop
                        }
                    }
                }
                
                if ($Passthru) { Get-CtxGroupPolicyFilter $PolicyName $FilterName -Type $Type -DriveName $DriveName }
            }
        }
    }
}

<#
    .SYNOPSIS
        Adds group policy filters.
    .DESCRIPTION
        This cmdlet adds group policy filters using the Citrix.Common.GroupPolicy provider.
    .PARAMETER  PolicyName
        The policy name.
    .PARAMETER  Type
        The policy type. Allowed values are User and Computer.
    .PARAMETER  FilterName
        The policy filter name.
    .PARAMETER  FilterType
        The policy filter type.
    .PARAMETER  FilterValue
        The policy filter value.
    .PARAMETER  Enabled
        The enabled state.
    .PARAMETER  Mode
        The policy filter mode. Allowed values are Allow and Deny.
    .PARAMETER  DriveName
        An optional drive name. Defaults to LocalFarmGpo.
    .EXAMPLE
        PS C:\> Add-CtxGroupPolicyFilter pol1 user filter1 workergroup wg1
        This command adds the worker group filter filter1 with value wg1 for user policy pol1.
    .INPUTS
        String.
    .OUTPUTS
        Policy object.
    .NOTES
    .LINK
        Get-CtxGroupPolicyFilter
        Set-CtxGroupPolicyFilter
        Remove-CtxGroupPolicyFilter
#>
Function Add-CtxGroupPolicyFilter
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string] $PolicyName,
        [Parameter(Position=1, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [String] [ValidateSet("Computer", "User")] $Type,
        [Parameter(Position=2, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string] $FilterName,
        [Parameter(Position=3, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string] $FilterType,
        [Parameter(Position=4, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string] $FilterValue,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string] $Enabled,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string] [ValidateSet("Allow", "Deny")] $Mode,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string] $AccessGatewayFarm,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string] $AccessCondition,
        [Parameter()]
        [string] $DriveName = "LocalFarmGpo"
    )

    process
    {
        $params = $PSCmdlet.MyInvocation.BoundParameters
        if ($PsCmdlet.ShouldProcess($FilterName))
        {
            if ($FilterType -eq "AccessControl")
            {
                "it is an access control filter named $FilterName"
                $item = New-Item "$($DriveName):\$Type\$PolicyName\Filters\$FilterType\$FilterName"
            }
            else 
            {
                "Filter named $FilterName with a value of $FilterValue"
                $item = New-Item "$($DriveName):\$Type\$PolicyName\Filters\$FilterType\$FilterName" $FilterValue -ErrorAction Stop
            }

            foreach ($prop in  "Enabled", "Mode", "AccessGatewayFarm", "AccessCondition" )
            {
                if ($params.ContainsKey($prop)) 
                {
                    "$prop :  $($params.$prop)"
                    Set-ItemProperty "$($DriveName):\$Type\$PolicyName\Filters\$FilterType\$FilterName" $prop $params.$prop
                }
            }
            Get-CtxGroupPolicyFilter $PolicyName $FilterName -Type $Type -DriveName $DriveName
        }
    }
}

<#
    .SYNOPSIS
        Removes group policy filters.
    .DESCRIPTION
        This cmdlet removes group policy filters using the Citrix.Common.GroupPolicy provider.
    .PARAMETER  PolicyName
        The policy name.
    .PARAMETER  Type
        The policy type. Allowed values are User and Computer.
    .PARAMETER  FilterName
        The policy filter name.
    .PARAMETER  FilterType
        The policy filter type.
    .PARAMETER  DriveName
        An optional drive name. Defaults to LocalFarmGpo.
    .EXAMPLE
        PS C:\> Remove-CtxGroupPolicyFilter pol1 user filter1 workergroup
        This command removes the filter filter1 from user policy pol1.
    .INPUTS
        String.
    .OUTPUTS
        Policy object.
    .NOTES
    .LINK
        Get-CtxGroupPolicyFilter
        Add-CtxGroupPolicyFilter
        Set-CtxGroupPolicyFilter
#>
Function Remove-CtxGroupPolicyFilter
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [String[]] $PolicyName,
        [Parameter(Position=1, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("Computer", "User")] [String] $Type,
        [Parameter(Position=2, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [String[]] $FilterName,
        [Parameter(Position=3, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string] $FilterType,
        [Parameter()]
        [string] $DriveName = "LocalFarmGpo",
        [Parameter()]
        [Switch] $Passthru
    )

    process
    {
        $filters = Get-CtxGroupPolicyFilter $PolicyName $Type $FilterName $FilterType -DriveName $DriveName -ErrorAction Stop
        foreach ($filter in $filters)
        {
            if ($PSCmdlet.ShouldProcess($filter.FilterName))
            {
                Remove-Item "$($DriveName):\$Type\$PolicyName\Filters\$FilterType\$FilterName"
                if ($Passthru) { $filter }
            }
        }
    }
}

#############################################

Function FilterString
{
    param([string] $value, [string[]] $wildcards)

    $wildcards | Where { $value -like $_ }
}

Function CreateDictionary
{
    return New-Object "System.Collections.Generic.Dictionary``2[System.String,System.Object]"
}

Function CreateObject
{
    param([System.Collections.IDictionary]$props, [string]$name)

    $obj = New-Object PSObject
    foreach ($prop in $props.Keys)
    {
        $obj | Add-Member NoteProperty -Name $prop -Value $props.$prop
    }
    if ($name)
    {
        $obj | Add-Member ScriptMethod -Name "ToString" -Value $executioncontext.invokecommand.NewScriptBlock('"{0}"' -f $name) -Force
    }
    return $obj
}

Function CompareObject
{
    param([PSObject] $NewObject, [PSObject] $CurrentObject)

    $props = CreateDictionary

    $oldprops = $CurrentObject | Get-Member -MemberType Properties | Select-Object -Expand Name
    $newprops = $NewObject | Get-Member -MemberType Properties | Select-Object -Expand Name
    ForEach($prop in $newprops)
    {
        if ($oldprops -contains $prop)
        {
            if (-not (AreValuesEqual $prop $NewObject.$prop $CurrentObject.$prop))
            {
                $props.$prop = $NewObject.$prop
            }
        }
    }
    if ($props.Keys.Count -gt 0)
    {
        CreateObject $props
    }
}

Function AreValuesEqual
{
    param($prop, $new, $old)

    if ($new -eq $null) { return $true }
    if ($old -eq $null) { return $false }

    if ($new -is [array])
    {
        return (Compare-Object $new $old | Measure-Object).Count -eq 0
    }
    if ($new -is [PSObject])
    {
        return (CompareObject $new $old) -eq $null
    }
    $equal = $new -eq $old
    if ($prop -eq "State")
    {
        switch($new)
        {
            "Enabled" { $equal = "Enabled", "Allowed" -contains $old }
            "Disabled" { $equal = "Disabled", "Prohibited", "UseDefault" -contains $old }
        }
    }
    return $equal
}

#################################

Export-ModuleMember -Function "*-*"
# SIG # Begin signature block
# MIIhUgYJKoZIhvcNAQcCoIIhQzCCIT8CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUriasqwFReka7txBdJMy5cNeZ
# VQGgghy8MIIDtzCCAp+gAwIBAgIQDOfg5RfYRv6P5WD8G/AwOTANBgkqhkiG9w0B
# AQUFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMDYxMTEwMDAwMDAwWhcNMzExMTEwMDAwMDAwWjBlMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3Qg
# Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtDhXO5EOAXLGH87dg
# +XESpa7cJpSIqvTO9SA5KFhgDPiA2qkVlTJhPLWxKISKityfCgyDF3qPkKyK53lT
# XDGEKvYPmDI2dsze3Tyoou9q+yHyUmHfnyDXH+Kx2f4YZNISW1/5WBg1vEfNoTb5
# a3/UsDg+wRvDjDPZ2C8Y/igPs6eD1sNuRMBhNZYW/lmci3Zt1/GiSw0r/wty2p5g
# 0I6QNcZ4VYcgoc/lbQrISXwxmDNsIumH0DJaoroTghHtORedmTpyoeb6pNnVFzF1
# roV9Iq4/AUaG9ih5yLHa5FcXxH4cDrC0kqZWs72yl+2qp/C3xag/lRbQ/6GW6whf
# GHdPAgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0G
# A1UdDgQWBBRF66Kv9JLLgjEtUYunpyGd823IDzAfBgNVHSMEGDAWgBRF66Kv9JLL
# gjEtUYunpyGd823IDzANBgkqhkiG9w0BAQUFAAOCAQEAog683+Lt8ONyc3pklL/3
# cmbYMuRCdWKuh+vy1dneVrOfzM4UKLkNl2BcEkxY5NM9g0lFWJc1aRqoR+pWxnmr
# EthngYTffwk8lOa4JiwgvT2zKIn3X/8i4peEH+ll74fg38FnSbNd67IJKusm7Xi+
# fT8r87cmNW1fiQG2SVufAQWbqz0lwcy2f8Lxb4bG+mRo64EtlOtCt/qMHt1i8b5Q
# Z7dsvfPxH2sMNgcWfzd8qVttevESRmCD1ycEvkvOl77DZypoEd+A5wwzZr8TDRRu
# 838fYxAe+o0bJW1sj6W3YQGx0qMmoRBxna3iw/nDmVG3KwcIzi7mULKn+gpFL6Lw
# 8jCCBRcwggP/oAMCAQICEAs/+4v3K5kWNoIKRSzDCywwDQYJKoZIhvcNAQEFBQAw
# bzELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEuMCwGA1UEAxMlRGlnaUNlcnQgQXNzdXJlZCBJRCBD
# b2RlIFNpZ25pbmcgQ0EtMTAeFw0xODAxMjQwMDAwMDBaFw0xODEwMDMxMjAwMDBa
# MGMxCzAJBgNVBAYTAlVTMRIwEAYDVQQIEwlUZW5uZXNzZWUxEjAQBgNVBAcTCVR1
# bGxhaG9tYTEVMBMGA1UEChMMQ2FybCBXZWJzdGVyMRUwEwYDVQQDEwxDYXJsIFdl
# YnN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDH/nMD6igNuEEO
# vbZVq8IgjA4AXGrSlDdTZWMN3UGjnlXtzIBEDh+aGhQLVZKouCZOYfTNhXAy5Ceu
# YuzV3c/aK3AozhzDjEnIb9tzL1P+NoqurIvQ11PR8mTPIbr4Y4CkwwHRbD9khZsm
# nzeDa+ndpFqHlXRgTRTwNC59I2A8V7TynrTFdHAAFAeciIgdxwNBvZFMB/4Rr25P
# 19Vfl+gLQ/Fe0NONkWRjvFdPayU5kxIfaXOnHdOHv6k+7S8eL70OkwYROHL0Ppw4
# nnv6skeedwEGh+FAsfBCOgCFe7Qqv5THdeeIx3aMEShgAghtdvP+JlqEZkmJGxv+
# JhH7G5I1AgMBAAGjggG5MIIBtTAfBgNVHSMEGDAWgBR7aM4pqsAXvkl64eU/1qf3
# RY81MjAdBgNVHQ4EFgQUQ+FwfwgCQpprAv5bJC0lEVQ6NC4wDgYDVR0PAQH/BAQD
# AgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMG0GA1UdHwRmMGQwMKAuoCyGKmh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9hc3N1cmVkLWNzLWcxLmNybDAwoC6gLIYqaHR0
# cDovL2NybDQuZGlnaWNlcnQuY29tL2Fzc3VyZWQtY3MtZzEuY3JsMEwGA1UdIARF
# MEMwNwYJYIZIAYb9bAMBMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2lj
# ZXJ0LmNvbS9DUFMwCAYGZ4EMAQQBMIGCBggrBgEFBQcBAQR2MHQwJAYIKwYBBQUH
# MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBMBggrBgEFBQcwAoZAaHR0cDov
# L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEQ29kZVNpZ25p
# bmdDQS0xLmNydDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBBQUAA4IBAQCG2/4m
# CXx6RqoW275xcEGAIrDibOBaB8AOunAkoQHN8j41/Nh+h4wuaL6yT+cKsUF5Oypk
# rKJmQIM1Y0nokG6fRtlrcddt+upV9i/4vgE8PtHlMYgkZpmCsjki43+HDcxBTSAg
# vM8UesAFHjD2QTCV5m8cMVl8735eVo+kY6u2QKfZa4Hz4q23uk6Zr6AtUFEdphR8
# i9UBUUs64nJq9NiANBkLq/CSxoB49j+9j1O1UW5hbr8SJE0PSVsZx1w8VggQPfMG
# igZeR8o2TNZQx3D+k/BCmblsFYsjQ1kV83npUkGIXkYtFJeyeEY8KjvY+IDMsQ9k
# ikgqJni2uJjdKEMYMIIGajCCBVKgAwIBAgIQAwGaAjr/WLFr1tXq5hfwZjANBgkq
# hkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBB
# c3N1cmVkIElEIENBLTEwHhcNMTQxMDIyMDAwMDAwWhcNMjQxMDIyMDAwMDAwWjBH
# MQswCQYDVQQGEwJVUzERMA8GA1UEChMIRGlnaUNlcnQxJTAjBgNVBAMTHERpZ2lD
# ZXJ0IFRpbWVzdGFtcCBSZXNwb25kZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
# ggEKAoIBAQCjZF38fLPggjXg4PbGKuZJdTvMbuBTqZ8fZFnmfGt/a4ydVfiS457V
# WmNbAklQ2YPOb2bu3cuF6V+l+dSHdIhEOxnJ5fWRn8YUOawk6qhLLJGJzF4o9GS2
# ULf1ErNzlgpno75hn67z/RJ4dQ6mWxT9RSOOhkRVfRiGBYxVh3lIRvfKDo2n3k5f
# 4qi2LVkCYYhhchhoubh87ubnNC8xd4EwH7s2AY3vJ+P3mvBMMWSN4+v6GYeofs/s
# jAw2W3rBerh4x8kGLkYQyI3oBGDbvHN0+k7Y/qpA8bLOcEaD6dpAoVk62RUJV5lW
# MJPzyWHM0AjMa+xiQpGsAsDvpPCJEY93AgMBAAGjggM1MIIDMTAOBgNVHQ8BAf8E
# BAMCB4AwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCCAb8G
# A1UdIASCAbYwggGyMIIBoQYJYIZIAYb9bAcBMIIBkjAoBggrBgEFBQcCARYcaHR0
# cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzCCAWQGCCsGAQUFBwICMIIBVh6CAVIA
# QQBuAHkAIAB1AHMAZQAgAG8AZgAgAHQAaABpAHMAIABDAGUAcgB0AGkAZgBpAGMA
# YQB0AGUAIABjAG8AbgBzAHQAaQB0AHUAdABlAHMAIABhAGMAYwBlAHAAdABhAG4A
# YwBlACAAbwBmACAAdABoAGUAIABEAGkAZwBpAEMAZQByAHQAIABDAFAALwBDAFAA
# UwAgAGEAbgBkACAAdABoAGUAIABSAGUAbAB5AGkAbgBnACAAUABhAHIAdAB5ACAA
# QQBnAHIAZQBlAG0AZQBuAHQAIAB3AGgAaQBjAGgAIABsAGkAbQBpAHQAIABsAGkA
# YQBiAGkAbABpAHQAeQAgAGEAbgBkACAAYQByAGUAIABpAG4AYwBvAHIAcABvAHIA
# YQB0AGUAZAAgAGgAZQByAGUAaQBuACAAYgB5ACAAcgBlAGYAZQByAGUAbgBjAGUA
# LjALBglghkgBhv1sAxUwHwYDVR0jBBgwFoAUFQASKxOYspkH7R7for5XDStnAs0w
# HQYDVR0OBBYEFGFaTSS2STKdSip5GoNL9B6Jwcp9MH0GA1UdHwR2MHQwOKA2oDSG
# Mmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRENBLTEu
# Y3JsMDigNqA0hjJodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1
# cmVkSURDQS0xLmNybDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEQ0EtMS5jcnQwDQYJKoZIhvcN
# AQEFBQADggEBAJ0lfhszTbImgVybhs4jIA+Ah+WI//+x1GosMe06FxlxF82pG7xa
# FjkAneNshORaQPveBgGMN/qbsZ0kfv4gpFetW7easGAm6mlXIV00Lx9xsIOUGQVr
# NZAQoHuXx/Y/5+IRQaa9YtnwJz04HShvOlIJ8OxwYtNiS7Dgc6aSwNOOMdgv420X
# Ewbu5AO2FKvzj0OncZ0h3RTKFV2SQdr5D4HRmXQNJsQOfxu19aDxxncGKBXp2JPl
# VRbwuwqrHNtcSCdmyKOLChzlldquxC5ZoGHd2vNtomHpigtt7BIYvfdVVEADkitr
# wlHCCkivsNRu4PQUCjob4489yq9qjXvc2EQwggajMIIFi6ADAgECAhAPqEkGFdcA
# oL4hdv3F7G29MA0GCSqGSIb3DQEBBQUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0xMTAyMTExMjAwMDBa
# Fw0yNjAyMTAxMjAwMDBaMG8xCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xLjAsBgNVBAMTJURpZ2lD
# ZXJ0IEFzc3VyZWQgSUQgQ29kZSBTaWduaW5nIENBLTEwggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQCcfPmgjwrKiUtTmjzsGSJ/DMv3SETQPyJumk/6zt/G
# 0ySR/6hSk+dy+PFGhpTFqxf0eH/Ler6QJhx8Uy/lg+e7agUozKAXEUsYIPO3vfLc
# y7iGQEUfT/k5mNM7629ppFwBLrFm6aa43Abero1i/kQngqkDw/7mJguTSXHlOG1O
# /oBcZ3e11W9mZJRru4hJaNjR9H4hwebFHsnglrgJlflLnq7MMb1qWkKnxAVHfWAr
# 2aFdvftWk+8b/HL53z4y/d0qLDJG2l5jvNC4y0wQNfxQX6xDRHz+hERQtIwqPXQM
# 9HqLckvgVrUTtmPpP05JI+cGFvAlqwH4KEHmx9RkO12rAgMBAAGjggNDMIIDPzAO
# BgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwggHDBgNVHSAEggG6
# MIIBtjCCAbIGCGCGSAGG/WwDMIIBpDA6BggrBgEFBQcCARYuaHR0cDovL3d3dy5k
# aWdpY2VydC5jb20vc3NsLWNwcy1yZXBvc2l0b3J5Lmh0bTCCAWQGCCsGAQUFBwIC
# MIIBVh6CAVIAQQBuAHkAIAB1AHMAZQAgAG8AZgAgAHQAaABpAHMAIABDAGUAcgB0
# AGkAZgBpAGMAYQB0AGUAIABjAG8AbgBzAHQAaQB0AHUAdABlAHMAIABhAGMAYwBl
# AHAAdABhAG4AYwBlACAAbwBmACAAdABoAGUAIABEAGkAZwBpAEMAZQByAHQAIABD
# AFAALwBDAFAAUwAgAGEAbgBkACAAdABoAGUAIABSAGUAbAB5AGkAbgBnACAAUABh
# AHIAdAB5ACAAQQBnAHIAZQBlAG0AZQBuAHQAIAB3AGgAaQBjAGgAIABsAGkAbQBp
# AHQAIABsAGkAYQBiAGkAbABpAHQAeQAgAGEAbgBkACAAYQByAGUAIABpAG4AYwBv
# AHIAcABvAHIAYQB0AGUAZAAgAGgAZQByAGUAaQBuACAAYgB5ACAAcgBlAGYAZQBy
# AGUAbgBjAGUALjASBgNVHRMBAf8ECDAGAQH/AgEAMHkGCCsGAQUFBwEBBG0wazAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAC
# hjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
# b290Q0EuY3J0MIGBBgNVHR8EejB4MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMDqgOKA2hjRodHRwOi8v
# Y3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMB0G
# A1UdDgQWBBR7aM4pqsAXvkl64eU/1qf3RY81MjAfBgNVHSMEGDAWgBRF66Kv9JLL
# gjEtUYunpyGd823IDzANBgkqhkiG9w0BAQUFAAOCAQEAe3IdZP+IyDrBt+nnqcSH
# u9uUkteQWTP6K4feqFuAJT8Tj5uDG3xDxOaM3zk+wxXssNo7ISV7JMFyXbhHkYET
# RvqcP2pRON60Jcvwq9/FKAFUeRBGJNE4DyahYZBNur0o5j/xxKqb9to1U0/J8j3T
# bNwj7aqgTWcJ8zqAPTz7NkyQ53ak3fI6v1Y1L6JMZejg1NrRx8iRai0jTzc7GZQY
# 1NWcEDzVsRwZ/4/Ia5ue+K6cmZZ40c2cURVbQiZyWo0KSiOSQOiG3iLCkzrUm2im
# 3yl/Brk8Dr2fxIacgkdCcTKGCZlyCXlLnXFp9UH/fzl3ZPGEjb6LHrJ9aKOlkLEM
# /zCCBs0wggW1oAMCAQICEAb9+QOWA63qAArrPye7uhswDQYJKoZIhvcNAQEFBQAw
# ZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBS
# b290IENBMB4XDTA2MTExMDAwMDAwMFoXDTIxMTExMDAwMDAwMFowYjELMAkGA1UE
# BhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2lj
# ZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgQXNzdXJlZCBJRCBDQS0xMIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6IItmfnKwkKVpYBzQHDSnlZUXKnE
# 0kEGj8kz/E1FkVyBn+0snPgWWd+etSQVwpi5tHdJ3InECtqvy15r7a2wcTHrzzpA
# DEZNk+yLejYIA6sMNP4YSYL+x8cxSIB8HqIPkg5QycaH6zY/2DDD/6b3+6LNb3Mj
# /qxWBZDwMiEWicZwiPkFl32jx0PdAug7Pe2xQaPtP77blUjE7h6z8rwMK5nQxl0S
# QoHhg26Ccz8mSxSQrllmCsSNvtLOBq6thG9IhJtPQLnxTPKvmPv2zkBdXPao8S+v
# 7Iki8msYZbHBc63X8djPHgp0XEK4aH631XcKJ1Z8D2KkPzIUYJX9BwSiCQIDAQAB
# o4IDejCCA3YwDgYDVR0PAQH/BAQDAgGGMDsGA1UdJQQ0MDIGCCsGAQUFBwMBBggr
# BgEFBQcDAgYIKwYBBQUHAwMGCCsGAQUFBwMEBggrBgEFBQcDCDCCAdIGA1UdIASC
# AckwggHFMIIBtAYKYIZIAYb9bAABBDCCAaQwOgYIKwYBBQUHAgEWLmh0dHA6Ly93
# d3cuZGlnaWNlcnQuY29tL3NzbC1jcHMtcmVwb3NpdG9yeS5odG0wggFkBggrBgEF
# BQcCAjCCAVYeggFSAEEAbgB5ACAAdQBzAGUAIABvAGYAIAB0AGgAaQBzACAAQwBl
# AHIAdABpAGYAaQBjAGEAdABlACAAYwBvAG4AcwB0AGkAdAB1AHQAZQBzACAAYQBj
# AGMAZQBwAHQAYQBuAGMAZQAgAG8AZgAgAHQAaABlACAARABpAGcAaQBDAGUAcgB0
# ACAAQwBQAC8AQwBQAFMAIABhAG4AZAAgAHQAaABlACAAUgBlAGwAeQBpAG4AZwAg
# AFAAYQByAHQAeQAgAEEAZwByAGUAZQBtAGUAbgB0ACAAdwBoAGkAYwBoACAAbABp
# AG0AaQB0ACAAbABpAGEAYgBpAGwAaQB0AHkAIABhAG4AZAAgAGEAcgBlACAAaQBu
# AGMAbwByAHAAbwByAGEAdABlAGQAIABoAGUAcgBlAGkAbgAgAGIAeQAgAHIAZQBm
# AGUAcgBlAG4AYwBlAC4wCwYJYIZIAYb9bAMVMBIGA1UdEwEB/wQIMAYBAf8CAQAw
# eQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vy
# dC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwgYEGA1UdHwR6MHgwOqA4oDaGNGh0
# dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5j
# cmwwOqA4oDaGNGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3Vy
# ZWRJRFJvb3RDQS5jcmwwHQYDVR0OBBYEFBUAEisTmLKZB+0e36K+Vw0rZwLNMB8G
# A1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA0GCSqGSIb3DQEBBQUAA4IB
# AQBGUD7Jtygkpzgdtlspr1LPUukxR6tWXHvVDQtBs+/sdR90OPKyXGGinJXDUOSC
# uSPRujqGcq04eKx1XRcXNHJHhZRW0eu7NoR3zCSl8wQZVann4+erYs37iy2QwsDS
# tZS9Xk+xBdIOPRqpFFumhjFiqKgz5Js5p8T1zh14dpQlc+Qqq8+cdkvtX8JLFuRL
# cEwAiR78xXm8TBJX/l/hHrwCXaj++wc4Tw3GXZG5D2dFzdaD7eeSDY2xaYxP+1ng
# Iw/Sqq4AfO6cQg7PkdcntxbuD8O9fAqg7iwIVYUiuOsYGk38KiGtSTGDR5V3cdyx
# G0tLHBCcdxTBnU8vWpUIKRAmMYIEADCCA/wCAQEwgYMwbzELMAkGA1UEBhMCVVMx
# FTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNv
# bTEuMCwGA1UEAxMlRGlnaUNlcnQgQXNzdXJlZCBJRCBDb2RlIFNpZ25pbmcgQ0Et
# MQIQCz/7i/crmRY2ggpFLMMLLDAJBgUrDgMCGgUAoEAwGQYJKoZIhvcNAQkDMQwG
# CisGAQQBgjcCAQQwIwYJKoZIhvcNAQkEMRYEFFuPkfoU4i2nVpDmwT6SnzGlAJA/
# MA0GCSqGSIb3DQEBAQUABIIBACMlbtge/j4VZPwIp8w2a4RJgbWoLU0G5s9/okkR
# ekod7NT+GNhYubVHESYAqvryr2DHsrvprGmkdf5fYsgEq/5vURg6aXBUQVgjSQmF
# +J9TpqD1TI4ljXabtLRtRU9yrdMqkIgiSSefS+rJuIUMAbL8DULDpIap3+qnFrDK
# uSRDc4ncCBLZFIRWHjiCdQC3NyuA/lLYYVLiASTTT6iyBWrjRRJ1oiHKZp850g6L
# nBQBzagZVXFzJ07mTDxIt1Uh8FvK56qtjHKBaPhJGWnVBeKVLS13KGT1EDPyUUex
# 6+IBaLTb6mqxMBDTvgoSL6+F2JQFllnNdcMGKsWVgyDDonqhggIPMIICCwYJKoZI
# hvcNAQkGMYIB/DCCAfgCAQEwdjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGln
# aUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhE
# aWdpQ2VydCBBc3N1cmVkIElEIENBLTECEAMBmgI6/1ixa9bV6uYX8GYwCQYFKw4D
# AhoFAKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8X
# DTE4MDkwNDE1MzUxOFowIwYJKoZIhvcNAQkEMRYEFC9zUXmuuGZlrhYKindL23Qc
# mvT7MA0GCSqGSIb3DQEBAQUABIIBAF4GbyqPOCIBOPumHPWJodCs1gNeuvXWtlQU
# VusD10O260YUBaceoNe+aU1fbOvy5Y2LgM1FvxPpBOFxeEQsH1kBV9HzFX7LyOmg
# kS7RudhutlnJVaGLLrF6CORPnL4cXaeXhbf0tH6H3+Hbn9NERHFG4q9NrylnZqJJ
# rZMFs+tsuEAEBmsgn2N9CkDeq0d0QusfnBnsDqAd/WIcp2NkYJTo/SCuyo070G8T
# zYJBbJz9y1SJ5WHI6lFj5hqxUo+06IjqXHaHn6rcquTwWjOpK2lXGli+YocTacUR
# uzoombDrpQPWk/zFmccMzzp7rvjXa/MNtScEARuzi+vaHfD58mg=
# SIG # End signature block
