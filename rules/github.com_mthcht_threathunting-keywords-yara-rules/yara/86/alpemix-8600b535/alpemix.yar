rule Alpemix
{
    meta:
        description = "Detection patterns for the tool 'Alpemix' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Alpemix"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/Alpemix\.zip/ nocase ascii wide
                        $string2 = /\/Apemix\.exe/ nocase ascii wide
                        $string3 = /\\Alpemix\.ini/ nocase ascii wide
                        $string4 = /\\Alpemix\.zip/ nocase ascii wide
                        $string5 = /\\Apemix\.exe/ nocase ascii wide
                        $string6 = /\\CurrentControlSet\\Services\\AlpemixSrvcx/ nocase ascii wide
                        $string7 = "<Alpemix>" nocase ascii wide
                        $string8 = "<AlpemixWEB>" nocase ascii wide
                        $string9 = "<Teknopars Bilisim>" nocase ascii wide
                        $string10 = "3660fe9f10b94d38fecaea009e6625850a46b1d47bb7788fc47f286c1008e2ec" nocase ascii wide
                        $string11 = "6badff5495258b349559b9d2154ffcc7a435828dd57c4caf1c79f5d0ff9eb675" nocase ascii wide
                        $string12 = "c5e68c5635bed872ce6ac0c2be5395cc15c2dbaa5f0052b86575cdd0b762902e" nocase ascii wide
                        $string13 = /serverinfo\.alpemix\.com/ nocase ascii wide

    condition:
        any of them
}