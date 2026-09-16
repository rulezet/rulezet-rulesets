rule Voidgate
{
    meta:
        description = "Detection patterns for the tool 'Voidgate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Voidgate"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Voidgate\.exe/ nocase ascii wide
                        $string2 = /\/Voidgate\.git/ nocase ascii wide
                        $string3 = /\\Voidgate\.cpp/ nocase ascii wide
                        $string4 = /\\Voidgate\.exe/ nocase ascii wide
                        $string5 = /\\voidgate\-master\\/ nocase ascii wide
                        $string6 = /\\Windows\\temp\\payload\.bin/ nocase ascii wide
                        $string7 = "15bdbbebff7a58257d1cd0ade5d76877259c2b3152508f1b2534a6fcab89cb38" nocase ascii wide
                        $string8 = "39fa3b4151fd83044106b63e95a820f4f1d769714d4f73369dba7a2187e0918b" nocase ascii wide
                        $string9 = "bba575ec-0c7f-42e1-9b59-b7c9cca522ba" nocase ascii wide
                        $string10 = "c06bb3f0-cbdc-4384-84cf-21b7fe6dfe01" nocase ascii wide
                        $string11 = "vxCrypt0r/Voidgate" nocase ascii wide
                        $string12 = /XorEncryptPayload\.cpp/ nocase ascii wide
                        $string13 = /XorEncryptPayload\.exe/ nocase ascii wide
                        $string14 = /XorEncryptPayload\.vcxproj/ nocase ascii wide

    condition:
        any of them
}