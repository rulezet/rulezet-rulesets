rule SilentCryptoMiner
{
    meta:
        description = "Detection patterns for the tool 'SilentCryptoMiner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SilentCryptoMiner"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/SilentCryptoMiner/" nocase ascii wide
                        $string2 = /\@etc\.2miners\.com\:/ nocase ascii wide
                        $string3 = /\\ethminer\.exe/ nocase ascii wide
                        $string4 = /\\MinerETH\.cs/ nocase ascii wide
                        $string5 = /\\MinerXMR\.cs/ nocase ascii wide
                        $string6 = /\\SilentCryptoMiner\\/ nocase ascii wide
                        $string7 = /\\SysWhispersU\.exe/ nocase ascii wide
                        $string8 = /\\xmrig\.exe/ nocase ascii wide
                        $string9 = /8BbApiMBHsPVKkLEP4rVbST6CnSb3LW2gXygngCi5MGiBuwAFh6bFEzT3UTufiCehFK7fNvAjs5Tv6BKYa6w8hwaSjnsg2N\./ nocase ascii wide
                        $string10 = /A\sSilent\s\(Hidden\)\sFree\sCrypto\sMiner\sBuilder/ nocase ascii wide
                        $string11 = "CE2307EB-A69E-0EB9-386C-D322223A10A9" nocase ascii wide
                        $string12 = "Company'>Unam Sanctam</Data>" nocase ascii wide
                        $string13 = "namespace SilentCryptoMiner" nocase ascii wide
                        $string14 = "Silent Crypto Miner Builder" nocase ascii wide
                        $string15 = /Silent\.Crypto\.Miner\.Builder\.zip/ nocase ascii wide
                        $string16 = /SilentCryptoMiner\.sln/ nocase ascii wide
                        $string17 = "SilentCryptoMiner-scm-v" nocase ascii wide
                        $string18 = /xmr\.2miners\.com/ nocase ascii wide
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