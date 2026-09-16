rule rule_libprocesshider_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'libprocesshider' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "libprocesshider"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_libprocesshider_offensive_tool_keyword = /\sevil_script\.py/
                        $string2_libprocesshider_offensive_tool_keyword = /\slibprocesshider\.so\s/
                        $string3_libprocesshider_offensive_tool_keyword = "/bin/processhider"
                        $string4_libprocesshider_offensive_tool_keyword = /\/evil_script\.py/
                        $string5_libprocesshider_offensive_tool_keyword = /\/libprocesshider\.git/
                        $string6_libprocesshider_offensive_tool_keyword = /\/libprocesshider\.so/
                        $string7_libprocesshider_offensive_tool_keyword = /\/processhider\.c/
                        $string8_libprocesshider_offensive_tool_keyword = /\\evil_script\.py/
                        $string9_libprocesshider_offensive_tool_keyword = "16d765e024adacabe84e9fd889030f5481546ef711bba0043e7e84eadd257d1a"
                        $string10_libprocesshider_offensive_tool_keyword = "eb5fee1e402f321c8e705776faf2be7bbede5d2a24fe3ac40be082a75429f927"
                        $string11_libprocesshider_offensive_tool_keyword = "gianlucaborello/libprocesshider"
                        $string12_libprocesshider_offensive_tool_keyword = /https\:\/\/sysdig\.com\/blog\/hiding\-linux\-processes\-for\-fun\-and\-profit\//
                        $string13_libprocesshider_offensive_tool_keyword = /sock\.send\(\\"\\"I\sAM\sA\sBAD\sBOY\\"\\"\)/
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