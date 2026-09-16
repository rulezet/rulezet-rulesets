rule netpass
{
    meta:
        description = "Detection patterns for the tool 'netpass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netpass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/utils\/network_password_recovery\.html/ nocase ascii wide
                        $string2 = "17fb52476016677db5a93505c4a1c356984bc1f6a4456870f920ac90a7846180" nocase ascii wide
                        $string3 = "17fb52476016677db5a93505c4a1c356984bc1f6a4456870f920ac90a7846180" nocase ascii wide
                        $string4 = "60724a25dd319ec57b77e16c52e52a09c7b82ed4ea38dab6d6c2e880dcebb439" nocase ascii wide
                        $string5 = /f\:\\temp\\pass\.html/ nocase ascii wide
                        $string6 = /netpass\.exe/ nocase ascii wide
                        $string7 = /netpass\.zip/ nocase ascii wide
                        $string8 = /netpass_x64\.exe/ nocase ascii wide
                        $string9 = /netpass\-x64\.zip/ nocase ascii wide
                        $string10 = "Network Password Recovery v" nocase ascii wide

    condition:
        any of them
}