rule rule_fetch_some_proxies_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'fetch-some-proxies' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fetch-some-proxies"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_fetch_some_proxies_offensive_tool_keyword = /\\"https\:\/\/api\.ipify\.org\/\?format\=text\\"\,\s\\"https\:\/\/myexternalip\.com\/raw\\"\,\s\\"https\:\/\/wtfismyip\.com\/text\\"\,\s\\"https\:\/\/icanhazip\.com\/\\"\,\s\\"https\:\/\/ip4\.seeip\.org\\"/ nocase ascii wide
                        $string2_fetch_some_proxies_offensive_tool_keyword = /\/fetch\-some\-proxies\.git/ nocase ascii wide
                        $string3_fetch_some_proxies_offensive_tool_keyword = /\|f\|\|e\|\|t\|\|c\|\|h\|\|\-\|\|s\|\|o\|\|m\|\|e\|\|\-\|\|p\|\|r\|\|o\|\|x\|\|i\|\|e\|\|s\|/ nocase ascii wide
                        $string4_fetch_some_proxies_offensive_tool_keyword = "daff98d2dd945ec0f5d8ef476de48e57074416a50389639d01aa54444d2cfb44" nocase ascii wide
                        $string5_fetch_some_proxies_offensive_tool_keyword = /https\:\/\/raw\.githubusercontent\.com\/stamparm\/aux\/master\/fetch\-some\-list\.txt/ nocase ascii wide
                        $string6_fetch_some_proxies_offensive_tool_keyword = "python -c \"import fetch\"" nocase ascii wide
                        $string7_fetch_some_proxies_offensive_tool_keyword = "stamparm/fetch-some-proxies" nocase ascii wide
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