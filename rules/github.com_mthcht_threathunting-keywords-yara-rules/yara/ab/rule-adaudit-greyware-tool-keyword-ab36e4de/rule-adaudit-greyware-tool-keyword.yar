rule rule_adaudit_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adaudit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adaudit"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_adaudit_greyware_tool_keyword = /\sadaudit\.ps1/ nocase ascii wide
                        $string2_adaudit_greyware_tool_keyword = /\/adaudit\.git/ nocase ascii wide
                        $string3_adaudit_greyware_tool_keyword = /\/adaudit\.ps1/ nocase ascii wide
                        $string4_adaudit_greyware_tool_keyword = /\[\!\]\sAS\-REP\sRoastable\suser\:/ nocase ascii wide
                        $string5_adaudit_greyware_tool_keyword = /\[\+\]\sNTDS\.dit\,\sSYSTEM\s\&\sSAM\ssaved\sto\soutput\sfolder/ nocase ascii wide
                        $string6_adaudit_greyware_tool_keyword = /\[\+\]\sUse\ssecretsdump\.py/ nocase ascii wide
                        $string7_adaudit_greyware_tool_keyword = /\\adaudit\.ps1/ nocase ascii wide
                        $string8_adaudit_greyware_tool_keyword = "54709655b001aa4d02b8040574970decd2e185a1ca4effbf87eb94574b9c87a0" nocase ascii wide
                        $string9_adaudit_greyware_tool_keyword = "Find-DangerousACLPermissions" nocase ascii wide
                        $string10_adaudit_greyware_tool_keyword = "Get-ADUsersWithoutPreAuth" nocase ascii wide
                        $string11_adaudit_greyware_tool_keyword = "phillips321/adaudit" nocase ascii wide
                        $string12_adaudit_greyware_tool_keyword = "Search-ADAccount -PasswordNeverExpires -UsersOnly" nocase ascii wide
                        $string13_adaudit_greyware_tool_keyword = /Write\-Nessus\-Finding\(/ nocase ascii wide

    condition:
        any of them
}