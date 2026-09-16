rule Shoggoth
{
    meta:
        description = "Detection patterns for the tool 'Shoggoth' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Shoggoth"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --coff-arg " nocase ascii wide
                        $string2 = /\sCOFFLoader\.exe/ nocase ascii wide
                        $string3 = /\sShoggoth\.exe/ nocase ascii wide
                        $string4 = /\#include\s\\"ShoggothEngine\.h\\"/ nocase ascii wide
                        $string5 = /\/beacon_generate\.py/ nocase ascii wide
                        $string6 = /\/COFFLoader\.exe/ nocase ascii wide
                        $string7 = /\/Shoggoth\.exe/ nocase ascii wide
                        $string8 = /\/Shoggoth\.git/ nocase ascii wide
                        $string9 = /\[\+\]\sCOFF\sLoader\smode\sis\sselected\!/ nocase ascii wide
                        $string10 = /\[\+\]\sPE\sLoader\smode\sis\sselected\!/ nocase ascii wide
                        $string11 = /\[\+\]\sPolymorphic\sencryption/ nocase ascii wide
                        $string12 = /\[\+\]\sShoggoth\sengine\sis\sinitiated\!/ nocase ascii wide
                        $string13 = /\\\\stub\\\\COFFLoader\.bin/ nocase ascii wide
                        $string14 = /\\COFFLoader\.exe/ nocase ascii wide
                        $string15 = /\\DumpNParse\.exe/ nocase ascii wide
                        $string16 = /\\Shoggoth\.exe/ nocase ascii wide
                        $string17 = /\\Shoggoth\.pptx/ nocase ascii wide
                        $string18 = /\\Shoggoth\.sln/ nocase ascii wide
                        $string19 = /\\ShoggothEngine\.cpp/ nocase ascii wide
                        $string20 = "1bc3fc0ecdae8f404c33942914e6f442ea91400bdea77322b318ab576d4050a9" nocase ascii wide
                        $string21 = "44D5BE95-F34D-4CC5-846F-C7758943B8FA" nocase ascii wide
                        $string22 = "9cbbb2ac103af9b7940ec72a8e430427d86f5099f7a537e4fe2b72d69e05bdfd" nocase ascii wide
                        $string23 = "'B','e','a','c','o','n'" nocase ascii wide
                        $string24 = /bin\/PELoader\.exe/ nocase ascii wide
                        $string25 = "d67630a3210bfcdd4b2fa2d48cdcdba0034710fd5ead616d9d5e4ce38e3c9809" nocase ascii wide
                        $string26 = "frkngksl/Shoggoth" nocase ascii wide
                        $string27 = "Shoggoth doesn't support x86 PE yet" nocase ascii wide
                        $string28 = /ShoggothPolyEngine\(/ nocase ascii wide

    condition:
        any of them
}