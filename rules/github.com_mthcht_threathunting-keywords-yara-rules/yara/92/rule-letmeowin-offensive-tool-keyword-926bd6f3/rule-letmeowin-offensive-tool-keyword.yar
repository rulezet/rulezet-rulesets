rule rule_LetMeowIn_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LetMeowIn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LetMeowIn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_LetMeowIn_offensive_tool_keyword = /\srestoresig\.py/ nocase ascii wide
                        $string2_LetMeowIn_offensive_tool_keyword = /\/LetMeowIn\.git/ nocase ascii wide
                        $string3_LetMeowIn_offensive_tool_keyword = /\/restoresig\.py/ nocase ascii wide
                        $string4_LetMeowIn_offensive_tool_keyword = /\\restoresig\.py/ nocase ascii wide
                        $string5_LetMeowIn_offensive_tool_keyword = "0x4d, 0x44, 0x4d, 0x50, 0x93, 0xa7, 0x00, 0x00" nocase ascii wide
                        $string6_LetMeowIn_offensive_tool_keyword = "736b362973af7010de9bf1cea58547a17a236e81a2084c344cf06a1b184698bb" nocase ascii wide
                        $string7_LetMeowIn_offensive_tool_keyword = /C\:\\\\temp\\\\debug\.dmp/ nocase ascii wide
                        $string8_LetMeowIn_offensive_tool_keyword = "Creating offline copies of the LSASS process to perform memory dumps on" nocase ascii wide
                        $string9_LetMeowIn_offensive_tool_keyword = "da5d6eca1efe3219fa8102a0afbf9823dc8b2c00dd53af20960ed29bca1b2cef" nocase ascii wide
                        $string10_LetMeowIn_offensive_tool_keyword = /Don\'t\sbe\sevil\swith\sthis\.\sI\screated\sthis\stool\sto\slearn/ nocase ascii wide
                        $string11_LetMeowIn_offensive_tool_keyword = /\'l\'\,\s\'s\'\,\s\'a\'\,\s\'s\'\,\s\'s\'\,\s\'\.\'\,\s\'e\'\,\s\'x\'\,\s\'e\'/ nocase ascii wide
                        $string12_LetMeowIn_offensive_tool_keyword = /L\'D\'\,\sL\'b\'\,\sL\'g\'\,\sL\'h\'\,\sL\'e\'\,\sL\'l\'\,\sL\'p\'\,\sL\'\.\'\,\sL\'d\'\,\sL\'l\'\,\sL\'l\'\,\sL\'\\0\'/ nocase ascii wide
                        $string13_LetMeowIn_offensive_tool_keyword = /LetMeowIn\.exe/ nocase ascii wide
                        $string14_LetMeowIn_offensive_tool_keyword = /LetMeowIn\-main\.zip/ nocase ascii wide
                        $string15_LetMeowIn_offensive_tool_keyword = /L\'n\'\,\sL\'t\'\,\sL\'d\'\,\sL\'l\'\,\sL\'l\'\,\sL\'\.\'\,\sL\'d\'\,\sL\'l\'\,\sL\'l\'\,\sL\'\\0\'/ nocase ascii wide
                        $string16_LetMeowIn_offensive_tool_keyword = "L'S', L'e', L'D', L'e', L'b', L'u', L'g', L'P', L'r', L'i', L'v', L'i', L'l', L'e', L'g', L'e'" nocase ascii wide
                        $string17_LetMeowIn_offensive_tool_keyword = "'M', 'i', 'n', 'i', 'D', 'u', 'm', 'p', 'W', 'r', 'i', 't', 'e', 'D', 'u', 'm', 'p'" nocase ascii wide
                        $string18_LetMeowIn_offensive_tool_keyword = "Meowmycks/LetMeowIn" nocase ascii wide
                        $string19_LetMeowIn_offensive_tool_keyword = /Try\sopening\sit\swith\sMimikatz\snow\s\:\)/ nocase ascii wide

    condition:
        any of them
}