rule rule_wcreddump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wcreddump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wcreddump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_wcreddump_offensive_tool_keyword = " install samdump2"
                        $string2_wcreddump_offensive_tool_keyword = /\swcreddump\s\(windows\scredentials\sdump\)/
                        $string3_wcreddump_offensive_tool_keyword = /\swcreddump\.py/
                        $string4_wcreddump_offensive_tool_keyword = /\sWINHELLO2hashcat\.py/
                        $string5_wcreddump_offensive_tool_keyword = /\/wcreddump\.git/
                        $string6_wcreddump_offensive_tool_keyword = /\/wcreddump\.py/
                        $string7_wcreddump_offensive_tool_keyword = /\/WINHELLO2hashcat\.py/
                        $string8_wcreddump_offensive_tool_keyword = /\\wcreddump\.py/
                        $string9_wcreddump_offensive_tool_keyword = /\\WINHELLO2hashcat\.py/
                        $string10_wcreddump_offensive_tool_keyword = "0d33356f9addc458bf9fc3861d9cafef954a51b66412b1cfc435eede351733f1"
                        $string11_wcreddump_offensive_tool_keyword = "samdump2 SYSTEM SAM"
                        $string12_wcreddump_offensive_tool_keyword = /succesfully\sdumped\sSAM\'s\shash\.es\sto\s/
                        $string13_wcreddump_offensive_tool_keyword = /succesfully\sdumped\sSAM\'s\shash\.es\sto\s/
                        $string14_wcreddump_offensive_tool_keyword = /succesfully\sdumped\sWINHELLO\spin\.s\sto\s/
                        $string15_wcreddump_offensive_tool_keyword = "truerustyy/wcreddump"

    condition:
        any of them
}