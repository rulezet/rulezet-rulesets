rule rule_kerbrute_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'kerbrute' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kerbrute"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_kerbrute_offensive_tool_keyword = " bruteuser " nocase ascii wide
                        $string2_kerbrute_offensive_tool_keyword = " bruteuser -d " nocase ascii wide
                        $string3_kerbrute_offensive_tool_keyword = /\skerbrute\.py/ nocase ascii wide
                        $string4_kerbrute_offensive_tool_keyword = " passwordspray -d " nocase ascii wide
                        $string5_kerbrute_offensive_tool_keyword = " --user-as-pass" nocase ascii wide
                        $string6_kerbrute_offensive_tool_keyword = /\suserenum\s\-d\s.{0,1000}\s.{0,1000}\.txt/ nocase ascii wide
                        $string7_kerbrute_offensive_tool_keyword = /\.\/kerbrute\s/
                        $string8_kerbrute_offensive_tool_keyword = /\/kerbrute\.git/ nocase ascii wide
                        $string9_kerbrute_offensive_tool_keyword = /\/kerbrute\.go/ nocase ascii wide
                        $string10_kerbrute_offensive_tool_keyword = /\/kerbrute\.py/ nocase ascii wide
                        $string11_kerbrute_offensive_tool_keyword = "/kerbrute/" nocase ascii wide
                        $string12_kerbrute_offensive_tool_keyword = /\/userenum\.go/ nocase ascii wide
                        $string13_kerbrute_offensive_tool_keyword = /\/userenum\.go/ nocase ascii wide
                        $string14_kerbrute_offensive_tool_keyword = /\\kerbrute\.py/ nocase ascii wide
                        $string15_kerbrute_offensive_tool_keyword = "ASRepToHashcat" nocase ascii wide
                        $string16_kerbrute_offensive_tool_keyword = /bruteforce\s.{0,1000}\.txt/ nocase ascii wide
                        $string17_kerbrute_offensive_tool_keyword = /bruteforce\.go/ nocase ascii wide
                        $string18_kerbrute_offensive_tool_keyword = "bruteForceCombos" nocase ascii wide
                        $string19_kerbrute_offensive_tool_keyword = "bruteForceUser" nocase ascii wide
                        $string20_kerbrute_offensive_tool_keyword = /bruteuser\.go/ nocase ascii wide
                        $string21_kerbrute_offensive_tool_keyword = "bruteuserCmd" nocase ascii wide
                        $string22_kerbrute_offensive_tool_keyword = /cmd\/bruteforce\.go/ nocase ascii wide
                        $string23_kerbrute_offensive_tool_keyword = /cmd\/bruteuser\.go/ nocase ascii wide
                        $string24_kerbrute_offensive_tool_keyword = /\-d\s.{0,1000}\sbruteforce\s\-/ nocase ascii wide
                        $string25_kerbrute_offensive_tool_keyword = /Got\sencrypted\sTGT\sfor\s.{0,1000}\sbut\scouldn\'t\sconvert\sto\shash/ nocase ascii wide
                        $string26_kerbrute_offensive_tool_keyword = /has\sno\spre\sauth\srequired\.\sDumping\shash\sto\scrack\soffline\:/ nocase ascii wide
                        $string27_kerbrute_offensive_tool_keyword = "install kerbrute" nocase ascii wide
                        $string28_kerbrute_offensive_tool_keyword = "kerbrute -" nocase ascii wide
                        $string29_kerbrute_offensive_tool_keyword = "kerbrute userenum " nocase ascii wide
                        $string30_kerbrute_offensive_tool_keyword = /kerbrute.{0,1000}bruteforce/ nocase ascii wide
                        $string31_kerbrute_offensive_tool_keyword = /kerbrute\.go/ nocase ascii wide
                        $string32_kerbrute_offensive_tool_keyword = "kerbrute/cmd" nocase ascii wide
                        $string33_kerbrute_offensive_tool_keyword = "kerbrute/util" nocase ascii wide
                        $string34_kerbrute_offensive_tool_keyword = /kerbrute_.{0,1000}\.exe/ nocase ascii wide
                        $string35_kerbrute_offensive_tool_keyword = "kerbrute_darwin_386"
                        $string36_kerbrute_offensive_tool_keyword = "kerbrute_darwin_amd64"
                        $string37_kerbrute_offensive_tool_keyword = "kerbrute_linux"
                        $string38_kerbrute_offensive_tool_keyword = "kerbrute_windows" nocase ascii wide
                        $string39_kerbrute_offensive_tool_keyword = /kerbrute_windows_386\.exe/ nocase ascii wide
                        $string40_kerbrute_offensive_tool_keyword = /kerbrute_windows_amd64\.exe/ nocase ascii wide
                        $string41_kerbrute_offensive_tool_keyword = "kerbrute-master" nocase ascii wide
                        $string42_kerbrute_offensive_tool_keyword = "KerbruteSession" nocase ascii wide
                        $string43_kerbrute_offensive_tool_keyword = /passwordspray.{0,1000}\-\-user\-as\-pass/ nocase ascii wide
                        $string44_kerbrute_offensive_tool_keyword = /passwordspray\.go/ nocase ascii wide
                        $string45_kerbrute_offensive_tool_keyword = "passwordSprayCmd" nocase ascii wide
                        $string46_kerbrute_offensive_tool_keyword = "ropnop/kerbrute" nocase ascii wide

    condition:
        any of them
}