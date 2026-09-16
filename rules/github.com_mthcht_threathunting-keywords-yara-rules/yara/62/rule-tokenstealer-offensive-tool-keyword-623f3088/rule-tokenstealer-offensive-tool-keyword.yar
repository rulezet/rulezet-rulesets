rule rule_TokenStealer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TokenStealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TokenStealer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_TokenStealer_offensive_tool_keyword = /\.exe\s\-u\s.{0,1000}\s\-s\s2\s\-c\scmd\.exe/ nocase ascii wide
                        $string2_TokenStealer_offensive_tool_keyword = /\/TokenStealer\.git/ nocase ascii wide
                        $string3_TokenStealer_offensive_tool_keyword = /\[\+\]\sMy\spersonal\ssimple\sand\sstupid\s\sToken\sStealer\.\.\.\s/ nocase ascii wide
                        $string4_TokenStealer_offensive_tool_keyword = /\[\+\]\sv1\.0\s\@decoder_it\s2023/ nocase ascii wide
                        $string5_TokenStealer_offensive_tool_keyword = /\]\sToken\sdoes\sNOT\shave\sSE_ASSIGN_PRIMARY_NAME.{0,1000}\susing\sCreateProcessAsWithToken\(\)\sfor\slaunching\:/ nocase ascii wide
                        $string6_TokenStealer_offensive_tool_keyword = "<SessionId>: list/steal token from specific session" nocase ascii wide
                        $string7_TokenStealer_offensive_tool_keyword = "ABC32DBD-B697-482D-A763-7BA82FE9CEA2" nocase ascii wide
                        $string8_TokenStealer_offensive_tool_keyword = "decoder-it/TokenStealer" nocase ascii wide
                        $string9_TokenStealer_offensive_tool_keyword = /list\/steal\stoken\sof\suser\s\<user\>.{0,1000}default\sNT\sAUTHORITY\\\\SYSTEM\sfor\scomamnd\sexecution/ nocase ascii wide
                        $string10_TokenStealer_offensive_tool_keyword = "-t: force use of Impersonation Privilege" nocase ascii wide
                        $string11_TokenStealer_offensive_tool_keyword = /TokenStealer\.cpp/ nocase ascii wide
                        $string12_TokenStealer_offensive_tool_keyword = /TokenStealer\.exe/ nocase ascii wide
                        $string13_TokenStealer_offensive_tool_keyword = /TokenStealer\.sln/ nocase ascii wide
                        $string14_TokenStealer_offensive_tool_keyword = /TokenStealer\.vcxproj/ nocase ascii wide
                        $string15_TokenStealer_offensive_tool_keyword = "TokenStealer-master" nocase ascii wide

    condition:
        any of them
}