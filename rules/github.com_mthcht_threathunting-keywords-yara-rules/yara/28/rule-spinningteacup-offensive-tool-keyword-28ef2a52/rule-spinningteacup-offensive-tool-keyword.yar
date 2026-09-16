rule rule_spinningteacup_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'spinningteacup' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spinningteacup"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_spinningteacup_offensive_tool_keyword = /\sspinningteacup\.py/ nocase ascii wide
                        $string2_spinningteacup_offensive_tool_keyword = /\svbarandomizer\.py/ nocase ascii wide
                        $string3_spinningteacup_offensive_tool_keyword = "\"This is a macro obfuscating framework\"" nocase ascii wide
                        $string4_spinningteacup_offensive_tool_keyword = /\.py\s.{0,1000}\.vba\s.{0,1000}\.vba\s\s\-\-norandomvariables\s\-\-math/ nocase ascii wide
                        $string5_spinningteacup_offensive_tool_keyword = /\.py\s.{0,1000}\.vba\s.{0,1000}\.vba\s\s\-\-wordlistpath\s.{0,1000}\s\-\-encodestring/ nocase ascii wide
                        $string6_spinningteacup_offensive_tool_keyword = /\.py\s.{0,1000}\.vba\s.{0,1000}\.vba\s\-\-randomcuts\s5\s10\s\-\-norandomint/ nocase ascii wide
                        $string7_spinningteacup_offensive_tool_keyword = /\.py\s.{0,1000}\.vba\s.{0,1000}\.vba\s\-\-usebusinesswords\s\-\-encodestring_calls/ nocase ascii wide
                        $string8_spinningteacup_offensive_tool_keyword = /\.py\s.{0,1000}\.vba\s.{0,1000}\.vba\s\-\-usebusinesswords\s\-\-math/ nocase ascii wide
                        $string9_spinningteacup_offensive_tool_keyword = /\/spinningteacup\.py/ nocase ascii wide
                        $string10_spinningteacup_offensive_tool_keyword = /\/vbarandomizer\.py/ nocase ascii wide
                        $string11_spinningteacup_offensive_tool_keyword = /\\spinningteacup\.py/ nocase ascii wide
                        $string12_spinningteacup_offensive_tool_keyword = /\\vbarandomizer\.py/ nocase ascii wide
                        $string13_spinningteacup_offensive_tool_keyword = "577b85630ecfd64d6817de11c4abf256512d299f70998c8c531202272123b202" nocase ascii wide
                        $string14_spinningteacup_offensive_tool_keyword = "attempt to randomize script without setting all randomizations methods" nocase ascii wide
                        $string15_spinningteacup_offensive_tool_keyword = /from\srandomizers\.vbarandomizer\simport\svbaRandomizer/ nocase ascii wide
                        $string16_spinningteacup_offensive_tool_keyword = "your script has been obfuscated and output to " nocase ascii wide

    condition:
        any of them
}