rule TokenStealer
{
    meta:
        description = "Detection patterns for the tool 'TokenStealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TokenStealer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe\s\-u\s.{0,1000}\s\-s\s2\s\-c\scmd\.exe/ nocase ascii wide
                        $string2 = /\/TokenStealer\.git/ nocase ascii wide
                        $string3 = /\[\+\]\sMy\spersonal\ssimple\sand\sstupid\s\sToken\sStealer\.\.\.\s/ nocase ascii wide
                        $string4 = /\[\+\]\sv1\.0\s\@decoder_it\s2023/ nocase ascii wide
                        $string5 = /\]\sToken\sdoes\sNOT\shave\sSE_ASSIGN_PRIMARY_NAME.{0,1000}\susing\sCreateProcessAsWithToken\(\)\sfor\slaunching\:/ nocase ascii wide
                        $string6 = "<SessionId>: list/steal token from specific session" nocase ascii wide
                        $string7 = "ABC32DBD-B697-482D-A763-7BA82FE9CEA2" nocase ascii wide
                        $string8 = "decoder-it/TokenStealer" nocase ascii wide
                        $string9 = /list\/steal\stoken\sof\suser\s\<user\>.{0,1000}default\sNT\sAUTHORITY\\\\SYSTEM\sfor\scomamnd\sexecution/ nocase ascii wide
                        $string10 = "-t: force use of Impersonation Privilege" nocase ascii wide
                        $string11 = /TokenStealer\.cpp/ nocase ascii wide
                        $string12 = /TokenStealer\.exe/ nocase ascii wide
                        $string13 = /TokenStealer\.sln/ nocase ascii wide
                        $string14 = /TokenStealer\.vcxproj/ nocase ascii wide
                        $string15 = "TokenStealer-master" nocase ascii wide

    condition:
        any of them
}