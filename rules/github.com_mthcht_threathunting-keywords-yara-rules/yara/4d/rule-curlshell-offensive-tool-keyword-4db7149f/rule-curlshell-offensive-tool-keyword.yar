rule rule_curlshell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'curlshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "curlshell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_curlshell_offensive_tool_keyword = /\scurlshell\.py/
                        $string2_curlshell_offensive_tool_keyword = /\.py\s.{0,100}0\.0\.0\.0.{0,100}\-\-serve\-forever/
                        $string3_curlshell_offensive_tool_keyword = /\.py\s.{0,100}\-\-dependabot\-workaround/
                        $string4_curlshell_offensive_tool_keyword = /\.py\s\-\-certificate\s.{0,100}\.pem\s\-\-private\-key\s.{0,100}\.pem\s\-\-listen\-port\s/
                        $string5_curlshell_offensive_tool_keyword = /\.py\s\-\-certificate\sfullchain\.pem\s\-\-private\-key\sprivkey\.pem\s\-\-listen\-port\s/
                        $string6_curlshell_offensive_tool_keyword = /\/curlshell\.git/ nocase ascii wide
                        $string7_curlshell_offensive_tool_keyword = /\/curlshell\.git/ nocase ascii wide
                        $string8_curlshell_offensive_tool_keyword = /\/curlshell\.py/ nocase ascii wide
                        $string9_curlshell_offensive_tool_keyword = /\/curlshell\-main\./ nocase ascii wide
                        $string10_curlshell_offensive_tool_keyword = "/curlshell-main/" nocase ascii wide
                        $string11_curlshell_offensive_tool_keyword = /\\curlshell\.py/ nocase ascii wide
                        $string12_curlshell_offensive_tool_keyword = /\\curlshell\-main/ nocase ascii wide
                        $string13_curlshell_offensive_tool_keyword = /\\curlshell\-main\\/ nocase ascii wide
                        $string14_curlshell_offensive_tool_keyword = "b8285e421d702738eab45670ecae439a7228994e7068b04cb51740e47efbfb41" nocase ascii wide
                        $string15_curlshell_offensive_tool_keyword = "curl https://curlshell"
                        $string16_curlshell_offensive_tool_keyword = /curlshell\.py/
                        $string17_curlshell_offensive_tool_keyword = "https://curlshell:"
                        $string18_curlshell_offensive_tool_keyword = /https\:\/\/curlshell\:.{0,100}\s\|\sbash/
                        $string19_curlshell_offensive_tool_keyword = "irsl/curlshell"
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