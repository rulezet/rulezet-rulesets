rule hakrawler
{
    meta:
        description = "Detection patterns for the tool 'hakrawler' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hakrawler"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/bin/hakrawler"
                        $string2 = /\/hakrawler\.git/
                        $string3 = /\|\shakrawler/
                        $string4 = "hakluke/hakrawler"
                        $string5 = "hakrawler -"
                        $string6 = /hakrawler\.go/
                        $string7 = "hakrawler@latest"
                        $string8 = "hakrawler-master"
                        $string9 = "haktrails subdomains"
                        $string10 = "install hakrawler"

    condition:
        any of them
}