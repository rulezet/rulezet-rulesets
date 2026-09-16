rule SMBeagle
{
    meta:
        description = "Detection patterns for the tool 'SMBeagle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SMBeagle"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --dont-enumerate-acls " nocase ascii wide
                        $string2 = /\s\-\-dont\-enumerate\-acls\s.{0,1000}\s\-e\s/ nocase ascii wide
                        $string3 = /\s\-\-scan\-local\-shares\s.{0,1000}\s\-e\s/ nocase ascii wide
                        $string4 = "/SharpShares/Enums" nocase ascii wide
                        $string5 = "/SMBeagle" nocase ascii wide
                        $string6 = /\\WindowsShareFinder\.cs/ nocase ascii wide
                        $string7 = /SMBeagle\.exe/ nocase ascii wide
                        $string8 = /SMBeagle\.sln/ nocase ascii wide
                        $string9 = /smbeagle_.{0,1000}_linux_amd64\.zip/
                        $string10 = /smbeagle_.{0,1000}_linux_arm64\.zip/
                        $string11 = /smbeagle_.{0,1000}_win_x64\.zip/ nocase ascii wide
                        $string12 = "using SMBeagle" nocase ascii wide
                        $string13 = /WindowsShareFinder\.cs/ nocase ascii wide

    condition:
        any of them
}