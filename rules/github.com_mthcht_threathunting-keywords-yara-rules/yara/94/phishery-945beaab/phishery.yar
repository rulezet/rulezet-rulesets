rule phishery
{
    meta:
        description = "Detection patterns for the tool 'phishery' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "phishery"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/phishery\.exe/ nocase ascii wide
                        $string2 = /\/phishery\.git/ nocase ascii wide
                        $string3 = "/phishery/releases/download/" nocase ascii wide
                        $string4 = /\\phishery\.exe/ nocase ascii wide
                        $string5 = "16bb30509efac0ba13c42eade477ab4454c5951c1c20f7c991c62798284aa3b0" nocase ascii wide
                        $string6 = "334a8657b76c88f5d7b6a2be78cc4e9e6c5ecaeea5a104cea5e6d0c4250674a7" nocase ascii wide
                        $string7 = "64591a6674fa71f5bf6858e009d487a56dc13d306cdab14a76e7b6fe49d4338b" nocase ascii wide
                        $string8 = "8fa8dcae188d04bb3bb48782d5f97019c3a122816d9f48a6a8554ce211acb1f8" nocase ascii wide
                        $string9 = "c2935d032a38a5a6d3251d22b9d93d08223b8dbf90efedbb0e6716cdafe76367" nocase ascii wide
                        $string10 = "fd36746c68cdf7b32e63adaaa7b3e863b9769582f703722b88d9bf0b94030434" nocase ascii wide
                        $string11 = "Injected Word document has been saved!" nocase ascii wide
                        $string12 = "ryhanson/phishery" nocase ascii wide

    condition:
        any of them
}