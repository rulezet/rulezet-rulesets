rule telebit_cloud
{
    meta:
        description = "Detection patterns for the tool 'telebit.cloud' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "telebit.cloud"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\.config\/telebit\/telebitd\.yml/ nocase ascii wide
                        $string2 = /\/cloud\.telebit\.remote\.plist/
                        $string3 = "/opt/telebit"
                        $string4 = "/telebit http "
                        $string5 = /\/telebit\.js\.git/
                        $string6 = /\/telebit\.service/
                        $string7 = "/telebit/var/log/"
                        $string8 = /\/telebit\-remote\.js/
                        $string9 = /bin\/telebit\.js/ nocase ascii wide
                        $string10 = /cloud\.telebit\.remot/ nocase ascii wide
                        $string11 = /https\:\/\/.{0,1000}\.telebit\.io/ nocase ascii wide
                        $string12 = /https\:\/\/get\.telebit\.io/ nocase ascii wide
                        $string13 = "install -g telebit" nocase ascii wide
                        $string14 = /netcat\s.{0,1000}\.telebit\.io/ nocase ascii wide
                        $string15 = /ssh\s\-o\s.{0,1000}\.telebit\.io/ nocase ascii wide
                        $string16 = /ssh.{0,1000}\.telebit\.cloud/ nocase ascii wide
                        $string17 = "telebit ssh auto" nocase ascii wide
                        $string18 = "telebit tcp " nocase ascii wide
                        $string19 = "--user-unit=telebit" nocase ascii wide

    condition:
        any of them
}