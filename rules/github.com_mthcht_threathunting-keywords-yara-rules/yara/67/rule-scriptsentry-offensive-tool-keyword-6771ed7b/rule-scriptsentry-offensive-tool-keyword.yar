rule rule_ScriptSentry_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ScriptSentry' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ScriptSentry"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ScriptSentry_offensive_tool_keyword = /\/ScriptSentry\.git/ nocase ascii wide
                        $string2_ScriptSentry_offensive_tool_keyword = /\/ScriptSentry\.ps1/ nocase ascii wide
                        $string3_ScriptSentry_offensive_tool_keyword = /\/ScriptSentry\.psd1/ nocase ascii wide
                        $string4_ScriptSentry_offensive_tool_keyword = /\/ScriptSentry\.psm1/ nocase ascii wide
                        $string5_ScriptSentry_offensive_tool_keyword = /\\ScriptSentry\.ps1/ nocase ascii wide
                        $string6_ScriptSentry_offensive_tool_keyword = /\\ScriptSentry\.psd1/ nocase ascii wide
                        $string7_ScriptSentry_offensive_tool_keyword = /\\ScriptSentry\.psm1/ nocase ascii wide
                        $string8_ScriptSentry_offensive_tool_keyword = /\\ScriptSentry\.txt/ nocase ascii wide
                        $string9_ScriptSentry_offensive_tool_keyword = "e1cd2b55-3b4f-41bd-a168-40db41e34349" nocase ascii wide
                        $string10_ScriptSentry_offensive_tool_keyword = /Find\-AdminLogonScripts\.ps1/ nocase ascii wide
                        $string11_ScriptSentry_offensive_tool_keyword = "Find-LogonScriptCredentials -LogonScripts" nocase ascii wide
                        $string12_ScriptSentry_offensive_tool_keyword = /Find\-LogonScriptCredentials\.ps1/ nocase ascii wide
                        $string13_ScriptSentry_offensive_tool_keyword = /Find\-UnsafeLogonScriptPermissions\.ps1/ nocase ascii wide
                        $string14_ScriptSentry_offensive_tool_keyword = "Find-UnsafeUNCPermissions -UNCScripts" nocase ascii wide
                        $string15_ScriptSentry_offensive_tool_keyword = /Find\-UnsafeUNCPermissions\.ps1/ nocase ascii wide
                        $string16_ScriptSentry_offensive_tool_keyword = /Get\-DomainAdmins\.ps1/ nocase ascii wide
                        $string17_ScriptSentry_offensive_tool_keyword = "Invoke-ScriptSentry" nocase ascii wide
                        $string18_ScriptSentry_offensive_tool_keyword = /ScriptSentry\-main\.zip/ nocase ascii wide
                        $string19_ScriptSentry_offensive_tool_keyword = "techspence/ScriptSentry" nocase ascii wide

    condition:
        any of them
}