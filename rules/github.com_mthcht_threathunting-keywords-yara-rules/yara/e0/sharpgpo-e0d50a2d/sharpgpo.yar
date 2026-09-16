rule SharpGpo
{
    meta:
        description = "Detection patterns for the tool 'SharpGpo' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpGpo"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --Action NewSecurityFiltering --GPOName " nocase ascii wide
                        $string2 = " --Action RemoveSecurityFiltering --GPOName " nocase ascii wide
                        $string3 = /\.exe\s\-\-Action\sGetGPLink\s\-\-/ nocase ascii wide
                        $string4 = /\.exe\s\-\-Action\sGetGPO\s\-\-/ nocase ascii wide
                        $string5 = /\.exe\s\-\-Action\sMoveObject\s\-\-/ nocase ascii wide
                        $string6 = /\.exe\s\-\-Action\sNewGPLink\s\-\-DN\s/ nocase ascii wide
                        $string7 = /\.exe\s\-\-Action\sRemoveGPLink\s\-\-DN\s/ nocase ascii wide
                        $string8 = /\.exe\s\-\-Action\sRemoveGPO\s\-\-/ nocase ascii wide
                        $string9 = /\.exe\s\-\-Action\sRemoveOU\s\-\-/ nocase ascii wide
                        $string10 = /\/SharpGpo\.exe/ nocase ascii wide
                        $string11 = /\\SharpGpo\.exe/ nocase ascii wide
                        $string12 = /\\SharpGPOAbuse\-master/ nocase ascii wide
                        $string13 = ">SharpGPO<" nocase ascii wide

    condition:
        any of them
}