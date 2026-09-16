rule kerbrute
{
    meta:
        description = "Detection patterns for the tool 'kerbrute' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kerbrute"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " bruteuser " nocase ascii wide
                        $string2 = " bruteuser -d " nocase ascii wide
                        $string3 = /\skerbrute\.py/ nocase ascii wide
                        $string4 = " passwordspray -d " nocase ascii wide
                        $string5 = " --user-as-pass" nocase ascii wide
                        $string6 = /\suserenum\s\-d\s.{0,1000}\s.{0,1000}\.txt/ nocase ascii wide
                        $string7 = /\.\/kerbrute\s/
                        $string8 = /\/kerbrute\.git/ nocase ascii wide
                        $string9 = /\/kerbrute\.go/ nocase ascii wide
                        $string10 = /\/kerbrute\.py/ nocase ascii wide
                        $string11 = "/kerbrute/" nocase ascii wide
                        $string12 = /\/userenum\.go/ nocase ascii wide
                        $string13 = /\/userenum\.go/ nocase ascii wide
                        $string14 = /\\kerbrute\.py/ nocase ascii wide
                        $string15 = "ASRepToHashcat" nocase ascii wide
                        $string16 = /bruteforce\s.{0,1000}\.txt/ nocase ascii wide
                        $string17 = /bruteforce\.go/ nocase ascii wide
                        $string18 = "bruteForceCombos" nocase ascii wide
                        $string19 = "bruteForceUser" nocase ascii wide
                        $string20 = /bruteuser\.go/ nocase ascii wide
                        $string21 = "bruteuserCmd" nocase ascii wide
                        $string22 = /cmd\/bruteforce\.go/ nocase ascii wide
                        $string23 = /cmd\/bruteuser\.go/ nocase ascii wide
                        $string24 = /\-d\s.{0,1000}\sbruteforce\s\-/ nocase ascii wide
                        $string25 = /Got\sencrypted\sTGT\sfor\s.{0,1000}\sbut\scouldn\'t\sconvert\sto\shash/ nocase ascii wide
                        $string26 = /has\sno\spre\sauth\srequired\.\sDumping\shash\sto\scrack\soffline\:/ nocase ascii wide
                        $string27 = "install kerbrute" nocase ascii wide
                        $string28 = "kerbrute -" nocase ascii wide
                        $string29 = "kerbrute userenum " nocase ascii wide
                        $string30 = /kerbrute.{0,1000}bruteforce/ nocase ascii wide
                        $string31 = /kerbrute\.go/ nocase ascii wide
                        $string32 = "kerbrute/cmd" nocase ascii wide
                        $string33 = "kerbrute/util" nocase ascii wide
                        $string34 = /kerbrute_.{0,1000}\.exe/ nocase ascii wide
                        $string35 = "kerbrute_darwin_386"
                        $string36 = "kerbrute_darwin_amd64"
                        $string37 = "kerbrute_linux"
                        $string38 = "kerbrute_windows" nocase ascii wide
                        $string39 = /kerbrute_windows_386\.exe/ nocase ascii wide
                        $string40 = /kerbrute_windows_amd64\.exe/ nocase ascii wide
                        $string41 = "kerbrute-master" nocase ascii wide
                        $string42 = "KerbruteSession" nocase ascii wide
                        $string43 = /passwordspray.{0,1000}\-\-user\-as\-pass/ nocase ascii wide
                        $string44 = /passwordspray\.go/ nocase ascii wide
                        $string45 = "passwordSprayCmd" nocase ascii wide
                        $string46 = "ropnop/kerbrute" nocase ascii wide

    condition:
        any of them
}