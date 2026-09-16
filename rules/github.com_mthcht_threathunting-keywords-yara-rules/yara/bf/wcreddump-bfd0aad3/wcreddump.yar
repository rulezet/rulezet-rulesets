rule wcreddump
{
    meta:
        description = "Detection patterns for the tool 'wcreddump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wcreddump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " install samdump2"
                        $string2 = /\swcreddump\s\(windows\scredentials\sdump\)/
                        $string3 = /\swcreddump\.py/
                        $string4 = /\sWINHELLO2hashcat\.py/
                        $string5 = /\/wcreddump\.git/
                        $string6 = /\/wcreddump\.py/
                        $string7 = /\/WINHELLO2hashcat\.py/
                        $string8 = /\\wcreddump\.py/
                        $string9 = /\\WINHELLO2hashcat\.py/
                        $string10 = "0d33356f9addc458bf9fc3861d9cafef954a51b66412b1cfc435eede351733f1"
                        $string11 = "samdump2 SYSTEM SAM"
                        $string12 = /succesfully\sdumped\sSAM\'s\shash\.es\sto\s/
                        $string13 = /succesfully\sdumped\sSAM\'s\shash\.es\sto\s/
                        $string14 = /succesfully\sdumped\sWINHELLO\spin\.s\sto\s/
                        $string15 = "truerustyy/wcreddump"

    condition:
        any of them
}