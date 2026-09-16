rule Invoke_SessionHunter
{
    meta:
        description = "Detection patterns for the tool 'Invoke-SessionHunter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-SessionHunter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Invoke\-SessionHunter\.git/ nocase ascii wide
                        $string2 = /\\Public\\Document\\SessionHunter\.txt/ nocase ascii wide
                        $string3 = "e721518ae125d596d4f5148ac0e7cc08d8b9efd62ce6d874fd5958e92b50346a" nocase ascii wide
                        $string4 = "fc0ceb113a9dd259d3f8029f0304e4be3ba72376a1d55b101b87b8d9e9b3a11a" nocase ascii wide
                        $string5 = "Invoke-SessionHunter " nocase ascii wide
                        $string6 = /Invoke\-SessionHunter\.ps1/ nocase ascii wide
                        $string7 = "Invoke-WMIRemoting " nocase ascii wide
                        $string8 = "Leo4j/Invoke-SessionHunter" nocase ascii wide

    condition:
        any of them
}