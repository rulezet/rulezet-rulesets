rule rule_SilentCryptoMiner_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SilentCryptoMiner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SilentCryptoMiner"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SilentCryptoMiner_offensive_tool_keyword = "/SilentCryptoMiner/" nocase ascii wide
                        $string2_SilentCryptoMiner_offensive_tool_keyword = /\@etc\.2miners\.com\:/ nocase ascii wide
                        $string3_SilentCryptoMiner_offensive_tool_keyword = /\\ethminer\.exe/ nocase ascii wide
                        $string4_SilentCryptoMiner_offensive_tool_keyword = /\\MinerETH\.cs/ nocase ascii wide
                        $string5_SilentCryptoMiner_offensive_tool_keyword = /\\MinerXMR\.cs/ nocase ascii wide
                        $string6_SilentCryptoMiner_offensive_tool_keyword = /\\SilentCryptoMiner\\/ nocase ascii wide
                        $string7_SilentCryptoMiner_offensive_tool_keyword = /\\SysWhispersU\.exe/ nocase ascii wide
                        $string8_SilentCryptoMiner_offensive_tool_keyword = /\\xmrig\.exe/ nocase ascii wide
                        $string9_SilentCryptoMiner_offensive_tool_keyword = /8BbApiMBHsPVKkLEP4rVbST6CnSb3LW2gXygngCi5MGiBuwAFh6bFEzT3UTufiCehFK7fNvAjs5Tv6BKYa6w8hwaSjnsg2N\./ nocase ascii wide
                        $string10_SilentCryptoMiner_offensive_tool_keyword = /A\sSilent\s\(Hidden\)\sFree\sCrypto\sMiner\sBuilder/ nocase ascii wide
                        $string11_SilentCryptoMiner_offensive_tool_keyword = "CE2307EB-A69E-0EB9-386C-D322223A10A9" nocase ascii wide
                        $string12_SilentCryptoMiner_offensive_tool_keyword = "Company'>Unam Sanctam</Data>" nocase ascii wide
                        $string13_SilentCryptoMiner_offensive_tool_keyword = "namespace SilentCryptoMiner" nocase ascii wide
                        $string14_SilentCryptoMiner_offensive_tool_keyword = "Silent Crypto Miner Builder" nocase ascii wide
                        $string15_SilentCryptoMiner_offensive_tool_keyword = /Silent\.Crypto\.Miner\.Builder\.zip/ nocase ascii wide
                        $string16_SilentCryptoMiner_offensive_tool_keyword = /SilentCryptoMiner\.sln/ nocase ascii wide
                        $string17_SilentCryptoMiner_offensive_tool_keyword = "SilentCryptoMiner-scm-v" nocase ascii wide
                        $string18_SilentCryptoMiner_offensive_tool_keyword = /xmr\.2miners\.com/ nocase ascii wide
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