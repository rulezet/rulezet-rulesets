rule LetMeowIn
{
    meta:
        description = "Detection patterns for the tool 'LetMeowIn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LetMeowIn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\srestoresig\.py/ nocase ascii wide
                        $string2 = /\/LetMeowIn\.git/ nocase ascii wide
                        $string3 = /\/restoresig\.py/ nocase ascii wide
                        $string4 = /\\restoresig\.py/ nocase ascii wide
                        $string5 = "0x4d, 0x44, 0x4d, 0x50, 0x93, 0xa7, 0x00, 0x00" nocase ascii wide
                        $string6 = "736b362973af7010de9bf1cea58547a17a236e81a2084c344cf06a1b184698bb" nocase ascii wide
                        $string7 = /C\:\\\\temp\\\\debug\.dmp/ nocase ascii wide
                        $string8 = "Creating offline copies of the LSASS process to perform memory dumps on" nocase ascii wide
                        $string9 = "da5d6eca1efe3219fa8102a0afbf9823dc8b2c00dd53af20960ed29bca1b2cef" nocase ascii wide
                        $string10 = /Don\'t\sbe\sevil\swith\sthis\.\sI\screated\sthis\stool\sto\slearn/ nocase ascii wide
                        $string11 = /\'l\'\,\s\'s\'\,\s\'a\'\,\s\'s\'\,\s\'s\'\,\s\'\.\'\,\s\'e\'\,\s\'x\'\,\s\'e\'/ nocase ascii wide
                        $string12 = /L\'D\'\,\sL\'b\'\,\sL\'g\'\,\sL\'h\'\,\sL\'e\'\,\sL\'l\'\,\sL\'p\'\,\sL\'\.\'\,\sL\'d\'\,\sL\'l\'\,\sL\'l\'\,\sL\'\\0\'/ nocase ascii wide
                        $string13 = /LetMeowIn\.exe/ nocase ascii wide
                        $string14 = /LetMeowIn\-main\.zip/ nocase ascii wide
                        $string15 = /L\'n\'\,\sL\'t\'\,\sL\'d\'\,\sL\'l\'\,\sL\'l\'\,\sL\'\.\'\,\sL\'d\'\,\sL\'l\'\,\sL\'l\'\,\sL\'\\0\'/ nocase ascii wide
                        $string16 = "L'S', L'e', L'D', L'e', L'b', L'u', L'g', L'P', L'r', L'i', L'v', L'i', L'l', L'e', L'g', L'e'" nocase ascii wide
                        $string17 = "'M', 'i', 'n', 'i', 'D', 'u', 'm', 'p', 'W', 'r', 'i', 't', 'e', 'D', 'u', 'm', 'p'" nocase ascii wide
                        $string18 = "Meowmycks/LetMeowIn" nocase ascii wide
                        $string19 = /Try\sopening\sit\swith\sMimikatz\snow\s\:\)/ nocase ascii wide

    condition:
        any of them
}