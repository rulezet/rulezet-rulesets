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

    condition:
        any of them
}