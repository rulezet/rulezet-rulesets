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
                        $string4_spinningteacup_offensive_tool_keyword = /\.py\s.{0,100}\.vba\s.{0,100}\.vba\s\s\-\-norandomvariables\s\-\-math/ nocase ascii wide
                        $string5_spinningteacup_offensive_tool_keyword = /\.py\s.{0,100}\.vba\s.{0,100}\.vba\s\s\-\-wordlistpath\s.{0,100}\s\-\-encodestring/ nocase ascii wide
                        $string6_spinningteacup_offensive_tool_keyword = /\.py\s.{0,100}\.vba\s.{0,100}\.vba\s\-\-randomcuts\s5\s10\s\-\-norandomint/ nocase ascii wide
                        $string7_spinningteacup_offensive_tool_keyword = /\.py\s.{0,100}\.vba\s.{0,100}\.vba\s\-\-usebusinesswords\s\-\-encodestring_calls/ nocase ascii wide
                        $string8_spinningteacup_offensive_tool_keyword = /\.py\s.{0,100}\.vba\s.{0,100}\.vba\s\-\-usebusinesswords\s\-\-math/ nocase ascii wide
                        $string9_spinningteacup_offensive_tool_keyword = /\/spinningteacup\.py/ nocase ascii wide
                        $string10_spinningteacup_offensive_tool_keyword = /\/vbarandomizer\.py/ nocase ascii wide
                        $string11_spinningteacup_offensive_tool_keyword = /\\spinningteacup\.py/ nocase ascii wide
                        $string12_spinningteacup_offensive_tool_keyword = /\\vbarandomizer\.py/ nocase ascii wide
                        $string13_spinningteacup_offensive_tool_keyword = "577b85630ecfd64d6817de11c4abf256512d299f70998c8c531202272123b202" nocase ascii wide
                        $string14_spinningteacup_offensive_tool_keyword = "attempt to randomize script without setting all randomizations methods" nocase ascii wide
                        $string15_spinningteacup_offensive_tool_keyword = /from\srandomizers\.vbarandomizer\simport\svbaRandomizer/ nocase ascii wide
                        $string16_spinningteacup_offensive_tool_keyword = "your script has been obfuscated and output to " nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}