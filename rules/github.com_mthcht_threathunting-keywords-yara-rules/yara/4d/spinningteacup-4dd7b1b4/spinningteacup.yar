rule spinningteacup
{
    meta:
        description = "Detection patterns for the tool 'spinningteacup' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spinningteacup"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sspinningteacup\.py/ nocase ascii wide
                        $string2 = /\svbarandomizer\.py/ nocase ascii wide
                        $string3 = "\"This is a macro obfuscating framework\"" nocase ascii wide
                        $string4 = /\.py\s.{0,1000}\.vba\s.{0,1000}\.vba\s\s\-\-norandomvariables\s\-\-math/ nocase ascii wide
                        $string5 = /\.py\s.{0,1000}\.vba\s.{0,1000}\.vba\s\s\-\-wordlistpath\s.{0,1000}\s\-\-encodestring/ nocase ascii wide
                        $string6 = /\.py\s.{0,1000}\.vba\s.{0,1000}\.vba\s\-\-randomcuts\s5\s10\s\-\-norandomint/ nocase ascii wide
                        $string7 = /\.py\s.{0,1000}\.vba\s.{0,1000}\.vba\s\-\-usebusinesswords\s\-\-encodestring_calls/ nocase ascii wide
                        $string8 = /\.py\s.{0,1000}\.vba\s.{0,1000}\.vba\s\-\-usebusinesswords\s\-\-math/ nocase ascii wide
                        $string9 = /\/spinningteacup\.py/ nocase ascii wide
                        $string10 = /\/vbarandomizer\.py/ nocase ascii wide
                        $string11 = /\\spinningteacup\.py/ nocase ascii wide
                        $string12 = /\\vbarandomizer\.py/ nocase ascii wide
                        $string13 = "577b85630ecfd64d6817de11c4abf256512d299f70998c8c531202272123b202" nocase ascii wide
                        $string14 = "attempt to randomize script without setting all randomizations methods" nocase ascii wide
                        $string15 = /from\srandomizers\.vbarandomizer\simport\svbaRandomizer/ nocase ascii wide
                        $string16 = "your script has been obfuscated and output to " nocase ascii wide

    condition:
        any of them
}