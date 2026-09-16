rule rule_DEDSEC_RANSOMWARE_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DEDSEC-RANSOMWARE' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DEDSEC-RANSOMWARE"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DEDSEC_RANSOMWARE_offensive_tool_keyword = /\.\/dedsec_ransomware/
                        $string2_DEDSEC_RANSOMWARE_offensive_tool_keyword = /\/DEDSEC\-RANSOMWARE\.git/ nocase ascii wide
                        $string3_DEDSEC_RANSOMWARE_offensive_tool_keyword = /\\Desktop\\.{0,1000}\.dedsec/ nocase ascii wide
                        $string4_DEDSEC_RANSOMWARE_offensive_tool_keyword = /\\Documents\\.{0,1000}\.dedsec/ nocase ascii wide
                        $string5_DEDSEC_RANSOMWARE_offensive_tool_keyword = "1da0b2abfcc58713bc8dd18ab16d9b9a9885ff813535ccd1e462fe7b979fd7871da0b2abfcc58713bc8dd18ab16d9b9a9885ff813535ccd1e462fe7b979fd787" nocase ascii wide
                        $string6_DEDSEC_RANSOMWARE_offensive_tool_keyword = "8a2f2dcdf0a2f4b3bf2c7ac94205e769dfcdb7c161df5a8d9df52935dbaeb936" nocase ascii wide
                        $string7_DEDSEC_RANSOMWARE_offensive_tool_keyword = "dedsec1da0b2abfcc58713bc8dd18ab16d9b9a9885ff813535ccd1e462fe7b979fd7871da0b2abfcc58713bc8dd18ab16d9b9a9885ff813535ccd1e462fe7b979fd787" nocase ascii wide
                        $string8_DEDSEC_RANSOMWARE_offensive_tool_keyword = /DEDSEC\-RANSOMWARE\.py/ nocase ascii wide
                        $string9_DEDSEC_RANSOMWARE_offensive_tool_keyword = /endswith\(\'\.dedsec\'\)/ nocase ascii wide
                        $string10_DEDSEC_RANSOMWARE_offensive_tool_keyword = "GludXhsb2NhbGhvc3Q2LjUuMC1rYWxpMi1hbWQ2NHg4Nc3Q2LjUuMC1rYWxpMi1hbWQ2NHg4Nc3Q2LjUuMC1rYWxpMi1hbWQ2NHg4Nc3Q2LjUuMC1rYWxpMi1hbWQ2NHg4Nl82NDE2MTM0ODExNjQ4NTAxMzg2MDQzMzky" nocase ascii wide
                        $string11_DEDSEC_RANSOMWARE_offensive_tool_keyword = /https\:\/\/discord\.com\/api\/webhooks\/1172456340560560180\/KwaMHIPwjfbQIhVUB\-mOHNRiHoNnyAzzQcvgvjJHqGAfLSXahTDKwB1SVuq__NVlPbeQ/ nocase ascii wide
                        $string12_DEDSEC_RANSOMWARE_offensive_tool_keyword = /https\:\/\/media0\.giphy\.com\/media\/l0IynvAIYxm8ZGUrm\/giphy\.gif\?cid\=ecf05e47qvbyv5iod2z91r9bufnpkvsjn1xm18a63b0g8z9a\&ep\=v1_gifs_related\&rid\=giphy\.gif\&ct\=g/ nocase ascii wide
                        $string13_DEDSEC_RANSOMWARE_offensive_tool_keyword = /https\:\/\/pyobfuscate\.com\/pyd/ nocase ascii wide
                        $string14_DEDSEC_RANSOMWARE_offensive_tool_keyword = /Oops\!\sYour\sfiles\shave\sbeen\sencrypted\..{0,1000}recover\sall\syour\sfiles\ssafely/ nocase ascii wide
                        $string15_DEDSEC_RANSOMWARE_offensive_tool_keyword = /t\.me\/dedsecransom/ nocase ascii wide
                        $string16_DEDSEC_RANSOMWARE_offensive_tool_keyword = "UklGRjT7DwBXQVZFZm10IBAAAAABAAEAgD4AAAB9AAACABAAZGF0YRD7DwD" nocase ascii wide
                        $string17_DEDSEC_RANSOMWARE_offensive_tool_keyword = "xelroth/DEDSEC-RANSOMWARE" nocase ascii wide
                        $string18_DEDSEC_RANSOMWARE_offensive_tool_keyword = "YOUR FILES HAVE BEEN SUCCESSFULLY DECRYPTED" nocase ascii wide

    condition:
        any of them
}