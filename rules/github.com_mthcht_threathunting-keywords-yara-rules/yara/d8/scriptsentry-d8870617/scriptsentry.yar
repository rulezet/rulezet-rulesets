rule ScriptSentry
{
    meta:
        description = "Detection patterns for the tool 'ScriptSentry' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ScriptSentry"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/ScriptSentry\.git/ nocase ascii wide
                        $string2 = /\/ScriptSentry\.ps1/ nocase ascii wide
                        $string3 = /\/ScriptSentry\.psd1/ nocase ascii wide
                        $string4 = /\/ScriptSentry\.psm1/ nocase ascii wide
                        $string5 = /\\ScriptSentry\.ps1/ nocase ascii wide
                        $string6 = /\\ScriptSentry\.psd1/ nocase ascii wide
                        $string7 = /\\ScriptSentry\.psm1/ nocase ascii wide
                        $string8 = /\\ScriptSentry\.txt/ nocase ascii wide
                        $string9 = "e1cd2b55-3b4f-41bd-a168-40db41e34349" nocase ascii wide
                        $string10 = /Find\-AdminLogonScripts\.ps1/ nocase ascii wide
                        $string11 = "Find-LogonScriptCredentials -LogonScripts" nocase ascii wide
                        $string12 = /Find\-LogonScriptCredentials\.ps1/ nocase ascii wide
                        $string13 = /Find\-UnsafeLogonScriptPermissions\.ps1/ nocase ascii wide
                        $string14 = "Find-UnsafeUNCPermissions -UNCScripts" nocase ascii wide
                        $string15 = /Find\-UnsafeUNCPermissions\.ps1/ nocase ascii wide
                        $string16 = /Get\-DomainAdmins\.ps1/ nocase ascii wide
                        $string17 = "Invoke-ScriptSentry" nocase ascii wide
                        $string18 = /ScriptSentry\-main\.zip/ nocase ascii wide
                        $string19 = "techspence/ScriptSentry" nocase ascii wide

    condition:
        any of them
}