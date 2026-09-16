rule rule_powercat_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'powercat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "powercat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_powercat_offensive_tool_keyword = /\s\-l\s\-p\s.{0,1000}\s\-e\scmd\s\-ge/ nocase ascii wide
                        $string2_powercat_offensive_tool_keyword = /\spowercat\.ps1/ nocase ascii wide
                        $string3_powercat_offensive_tool_keyword = /\.ps1\s\-l\s\-p\s.{0,1000}\s\-r\sdns\:\:\:/ nocase ascii wide
                        $string4_powercat_offensive_tool_keyword = /\/powercat\.git/ nocase ascii wide
                        $string5_powercat_offensive_tool_keyword = /\/powercat\.ps1/ nocase ascii wide
                        $string6_powercat_offensive_tool_keyword = /\\powercat\.ps1/ nocase ascii wide
                        $string7_powercat_offensive_tool_keyword = /\\powercat\-master\\/ nocase ascii wide
                        $string8_powercat_offensive_tool_keyword = "79acacd2433990d8fe71ee9583123240b34ae26f4913d62b796238f4a302e104" nocase ascii wide
                        $string9_powercat_offensive_tool_keyword = "besimorhino/powercat" nocase ascii wide
                        $string10_powercat_offensive_tool_keyword = "f75cca99da6b3693e3310767256f62228a4451435e4f4301fa7dc95bef9c92ff" nocase ascii wide
                        $string11_powercat_offensive_tool_keyword = "powercat -c " nocase ascii wide
                        $string12_powercat_offensive_tool_keyword = "powercat -l " nocase ascii wide
                        $string13_powercat_offensive_tool_keyword = /Write\-Verbose\s\(\\"Listening\son\s\[0\.0\.0\.0\]\sport/ nocase ascii wide

    condition:
        any of them
}