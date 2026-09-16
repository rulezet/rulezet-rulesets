rule rule_SMBeagle_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SMBeagle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SMBeagle"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SMBeagle_offensive_tool_keyword = " --dont-enumerate-acls " nocase ascii wide
                        $string2_SMBeagle_offensive_tool_keyword = /\s\-\-dont\-enumerate\-acls\s.{0,1000}\s\-e\s/ nocase ascii wide
                        $string3_SMBeagle_offensive_tool_keyword = /\s\-\-scan\-local\-shares\s.{0,1000}\s\-e\s/ nocase ascii wide
                        $string4_SMBeagle_offensive_tool_keyword = "/SharpShares/Enums" nocase ascii wide
                        $string5_SMBeagle_offensive_tool_keyword = "/SMBeagle" nocase ascii wide
                        $string6_SMBeagle_offensive_tool_keyword = /\\WindowsShareFinder\.cs/ nocase ascii wide
                        $string7_SMBeagle_offensive_tool_keyword = /SMBeagle\.exe/ nocase ascii wide
                        $string8_SMBeagle_offensive_tool_keyword = /SMBeagle\.sln/ nocase ascii wide
                        $string9_SMBeagle_offensive_tool_keyword = /smbeagle_.{0,1000}_linux_amd64\.zip/
                        $string10_SMBeagle_offensive_tool_keyword = /smbeagle_.{0,1000}_linux_arm64\.zip/
                        $string11_SMBeagle_offensive_tool_keyword = /smbeagle_.{0,1000}_win_x64\.zip/ nocase ascii wide
                        $string12_SMBeagle_offensive_tool_keyword = "using SMBeagle" nocase ascii wide
                        $string13_SMBeagle_offensive_tool_keyword = /WindowsShareFinder\.cs/ nocase ascii wide

    condition:
        any of them
}