rule hiphp
{
    meta:
        description = "Detection patterns for the tool 'hiphp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hiphp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\shiphp\-cli\.sh/ nocase ascii wide
                        $string2 = /\shiphp\-desktop\.sh/ nocase ascii wide
                        $string3 = " -i -t hiphp:latest" nocase ascii wide
                        $string4 = /\/hiphp\.git/ nocase ascii wide
                        $string5 = /\/hiphp\-cli\.sh/ nocase ascii wide
                        $string6 = /\/hiphp\-desktop\.sh/ nocase ascii wide
                        $string7 = "/hiphp-main" nocase ascii wide
                        $string8 = /\\hiphp\-cli\.sh/ nocase ascii wide
                        $string9 = /\\hiphp\-desktop\.sh/ nocase ascii wide
                        $string10 = "docker build -t hiphp:latest" nocase ascii wide
                        $string11 = /docker.{0,1000}\/hiphp\:latest/ nocase ascii wide
                        $string12 = "e7370f93d1d0cde622a1f8e1c04877d8463912d04d973331ad4851f04de6915a" nocase ascii wide
                        $string13 = "from hiphp import " nocase ascii wide
                        $string14 = /hiphp\s.{0,1000}\-\-url/ nocase ascii wide
                        $string15 = /hiphp\.hiphplinkextractor/ nocase ascii wide
                        $string16 = /hiphp\.hiphpversion/ nocase ascii wide
                        $string17 = /hiphp\-0\.3\.4\.deb/ nocase ascii wide
                        $string18 = /hiphp\-0\.3\.5\.deb/ nocase ascii wide
                        $string19 = /hiphp\-0\.3\.6\.deb/ nocase ascii wide
                        $string20 = /hiphp\-1\..{0,1000}\..{0,1000}\.deb/ nocase ascii wide
                        $string21 = /hiphp\-cli\.bat/ nocase ascii wide
                        $string22 = /hiphp\-desktop\.bat/ nocase ascii wide
                        $string23 = /hiphp\-termux\.sh/ nocase ascii wide
                        $string24 = /hiphp\-tk\.bat/ nocase ascii wide
                        $string25 = "Killing ngrok tunnel" nocase ascii wide
                        $string26 = "pip install hiphp" nocase ascii wide
                        $string27 = /python\smain\.py\s\-\-KEY\=.{0,1000}\s\-\-URL\=.{0,1000}127\.0\.0\.1/ nocase ascii wide
                        $string28 = /run\-hiphp\-tk\.sh/ nocase ascii wide
                        $string29 = /share\/hiphp\.py/ nocase ascii wide
                        $string30 = "yasserbdj96/hiphp" nocase ascii wide

    condition:
        any of them
}