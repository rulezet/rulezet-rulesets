rule rule_GetLoggedOnUsersRegistry_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GetLoggedOnUsersRegistry' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GetLoggedOnUsersRegistry"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GetLoggedOnUsersRegistry_offensive_tool_keyword = /\]\sAttempting\sto\senumerate\slogged\son\susers\son\s/ nocase ascii wide
                        $string2_GetLoggedOnUsersRegistry_offensive_tool_keyword = /GetLoggedOnUsersRegistry\.cs/ nocase ascii wide
                        $string3_GetLoggedOnUsersRegistry_offensive_tool_keyword = "PoC To enumerate logged on users on a remote system using the winreg named pipe" nocase ascii wide
                        $string4_GetLoggedOnUsersRegistry_offensive_tool_keyword = "RalphDesmangles/22f580655f479f189c1de9e7720776f1" nocase ascii wide

    condition:
        any of them
}