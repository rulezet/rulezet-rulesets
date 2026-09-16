rule Godzilla
{
    meta:
        description = "Detection patterns for the tool 'Godzilla' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Godzilla"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /Backdoor\:ASP\/Chopper\.ZC\!dha/ nocase ascii wide
                        $string2 = "TrojanDownloader:Java/GodzillaWebShell" nocase ascii wide
                        $string3 = /TrojanDownloader\:Java\/GodzillaWebShell\.C/ nocase ascii wide
                        $string4 = /VirTool\:MSIL\/DarkStealer\.A\!MTB/ nocase ascii wide

    condition:
        any of them
}