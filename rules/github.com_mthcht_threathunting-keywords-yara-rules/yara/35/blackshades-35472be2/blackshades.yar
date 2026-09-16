rule BlackShades
{
    meta:
        description = "Detection patterns for the tool 'BlackShades' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BlackShades"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\\"keylog\.php\\"/ nocase ascii wide
                        $string2 = /\/keylog\.php/ nocase ascii wide
                        $string3 = ">Blackshades NET<" nocase ascii wide
                        $string4 = "2720ade6e794942ef6b2340db083e2e8ae392ca5ca08e71aae5329865b13e814" nocase ascii wide
                        $string5 = "4b7a6d90bd88298bc472e3f092cb4d1f60b46f5530b0e4d3b85dd236cbd17b92" nocase ascii wide
                        $string6 = "6f3476967a8ef65e491229af8ddfb6a9958a346f151b9bce48122e1a04b97539" nocase ascii wide
                        $string7 = "71b9c3db10f12ee563c0668b04171ca99e79ab1cd09911bc79f061d6d3da544d" nocase ascii wide
                        $string8 = "Blackshades Database Viewer" nocase ascii wide
                        $string9 = "Blackshades NET Web Server" nocase ascii wide
                        $string10 = "e024e14ccb85b8c59cfc10ee2d9aa867c85e036382363fd8581c97ecaaf10fb4" nocase ascii wide
                        $string11 = /http\:\/\/bshades\.eu/ nocase ascii wide

    condition:
        any of them
}