rule rule_SharpShares_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpShares' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpShares"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpShares_offensive_tool_keyword = /\(\&\(objectCategory\=computer\)\(\!\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=2\)\)\(\!\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=8192\)\)\(\!\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=67100867\)\)\)/ nocase ascii wide
                        $string2_SharpShares_offensive_tool_keyword = /\(\&\(objectCategory\=computer\)\(\!\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=2\)\)\(operatingSystem\=.{0,100}server.{0,100}\)\(\!\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=8192\)\)\(\!\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=67100867\)\)\)/ nocase ascii wide
                        $string3_SharpShares_offensive_tool_keyword = /\(\&\(objectCategory\=computer\)\(\!\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=2\)\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=8192\)\)/ nocase ascii wide
                        $string4_SharpShares_offensive_tool_keyword = /\/SharpShares\.git/ nocase ascii wide
                        $string5_SharpShares_offensive_tool_keyword = "/SharpShares/releases/download/" nocase ascii wide
                        $string6_SharpShares_offensive_tool_keyword = "/SharpShares-master" nocase ascii wide
                        $string7_SharpShares_offensive_tool_keyword = /\[\+\]\sFinished\sEnumerating\sShares/ nocase ascii wide
                        $string8_SharpShares_offensive_tool_keyword = /\[\+\]\sQuerying\sDC\swithout\sGlobal\sCatalog\:\s/ nocase ascii wide
                        $string9_SharpShares_offensive_tool_keyword = /\[\+\]\sStarting\sshare\senumeration\sagainst\s.{0,100}\shosts/ nocase ascii wide
                        $string10_SharpShares_offensive_tool_keyword = /\\SharpShares\\/ nocase ascii wide
                        $string11_SharpShares_offensive_tool_keyword = /\\SharpShares\-master/ nocase ascii wide
                        $string12_SharpShares_offensive_tool_keyword = /\]\sStarting\sshare\senumeration\swith\sthread\slimit\sof\s/ nocase ascii wide
                        $string13_SharpShares_offensive_tool_keyword = ">SharpShares<" nocase ascii wide
                        $string14_SharpShares_offensive_tool_keyword = "12c9cf22a8a7c652c7ea63dbbdf7ffac3052ca6b49828d03261cc258d95afeef" nocase ascii wide
                        $string15_SharpShares_offensive_tool_keyword = "1d0e8e47b8cada01b881d1685096940d044c0729cfe0071b4c7571c55737d0dc" nocase ascii wide
                        $string16_SharpShares_offensive_tool_keyword = "1fcdf70d9d7546a68df3ef27d3cb8eee7a125cb1a27de14ea8a2c3460275379d" nocase ascii wide
                        $string17_SharpShares_offensive_tool_keyword = "214adf5acd24740909da1a8ee95d629da354cbe23bc2b56d7edf610c84bd6a1d" nocase ascii wide
                        $string18_SharpShares_offensive_tool_keyword = "2b67fbf351f08b878a611aeceb69fd1825f2c804b78aec158d56cba58b65a378" nocase ascii wide
                        $string19_SharpShares_offensive_tool_keyword = "2e93e83a8c1671dec1b0b4a9873025f47567a1092e12bcfe14d1f78e5696aaeb" nocase ascii wide
                        $string20_SharpShares_offensive_tool_keyword = "32858fab2bfbbde5516cdcf181d96b25960071b1516fec04b03f96d2fa5395d7" nocase ascii wide
                        $string21_SharpShares_offensive_tool_keyword = "3a9144c6468bfab90def18913d6119462ae1e972f4dc0c1ce0f9492afe3861c0" nocase ascii wide
                        $string22_SharpShares_offensive_tool_keyword = "3f9462dec07f9859ce437efe0a77ed335b07a47d2ce33b6bed3153aa3a1512d4" nocase ascii wide
                        $string23_SharpShares_offensive_tool_keyword = "56a4d640936bc70b69883f930565e6abb43377e498836da5e8eba7d5f4f7acf9" nocase ascii wide
                        $string24_SharpShares_offensive_tool_keyword = "56cd70d3ff5abc405f93173f800ce0f9e641d4f979e395e3c9e7e9e61f8b1e5f" nocase ascii wide
                        $string25_SharpShares_offensive_tool_keyword = "683ed7b04ebf596dbfdd30456656bed8c1a8f8ee4b8eec411ad8bce572e10240" nocase ascii wide
                        $string26_SharpShares_offensive_tool_keyword = "6b45295ad89a7ecb49f612579ee05ea4b8617ac14f7026f15dc3395244b44c99" nocase ascii wide
                        $string27_SharpShares_offensive_tool_keyword = "793bb27999fa08b9b9f9e58027be7444bbaa2d71786baa37bd9955a645fa7d21" nocase ascii wide
                        $string28_SharpShares_offensive_tool_keyword = "7a69936f724eb8af4e5a8052de3420c2359158ced63b66ae41fd6fe08c9542a8" nocase ascii wide
                        $string29_SharpShares_offensive_tool_keyword = "7be59deb0b1db3b7898139b7f5575ddedd5ed91e964bdb54546bb3bfd6d3eec1" nocase ascii wide
                        $string30_SharpShares_offensive_tool_keyword = "8011deee58ffff8edb641b0c964481a3f1e00978abc96904c1922d1ac88e243a" nocase ascii wide
                        $string31_SharpShares_offensive_tool_keyword = "808843c9419ba2e42881ef4f4ad3087874d3d7088d16fb6dbf6508f05a1189c8" nocase ascii wide
                        $string32_SharpShares_offensive_tool_keyword = "92576b05b8f8f5ed4571e1e165fff1ea271b626cad0f6f71e995d24a1fa427b5" nocase ascii wide
                        $string33_SharpShares_offensive_tool_keyword = "9379882ba3635ecf7bbd140a313245e551acb1a702b1e5e514eb61bf76260a83" nocase ascii wide
                        $string34_SharpShares_offensive_tool_keyword = "9404a903396f378796bc906ecab923f471cd6228c646cd13afe55948c414a4b2" nocase ascii wide
                        $string35_SharpShares_offensive_tool_keyword = "993e5580a5eecf984fad97f7925ee12f86f83f1088b56dd71645bf6deb97118c" nocase ascii wide
                        $string36_SharpShares_offensive_tool_keyword = "995f304132e68eb63d3901bb9e672853eb36859aece625983c4ed690ccf2bcd8" nocase ascii wide
                        $string37_SharpShares_offensive_tool_keyword = "a3082e1d9f46b7d8878e3a87a0324eabff9731c12e8637e0a714929938a99177" nocase ascii wide
                        $string38_SharpShares_offensive_tool_keyword = "bbdd3620a67aedec4b9a68b2c9cc880b6631215e129816aea19902a6f4bc6f41" nocase ascii wide
                        $string39_SharpShares_offensive_tool_keyword = "BCBC884D-2D47-4138-B68F-7D425C9291F9" nocase ascii wide
                        $string40_SharpShares_offensive_tool_keyword = "bf8830d8ce61d2cb357a1f8a394f3220f9eaa02f436ab4bd98edb567b149c754" nocase ascii wide
                        $string41_SharpShares_offensive_tool_keyword = "c1ce14f634f6ed7a60ac4e69d35eb745c2238408ec5c6faacde3489b04f64e7d" nocase ascii wide
                        $string42_SharpShares_offensive_tool_keyword = "e11e7db705a11f8ca250d8d6826371e550b3214757f5bb9b648c7b0fad09294b" nocase ascii wide
                        $string43_SharpShares_offensive_tool_keyword = "e1792577b8a2878c0ee0e02c94c3113ed483e99e4d20d716f1c4c7589076f06b" nocase ascii wide
                        $string44_SharpShares_offensive_tool_keyword = "e53c37e94cfa66023839a9db008e7953f524db0dd6b5f1a467f1a55827aa63df" nocase ascii wide
                        $string45_SharpShares_offensive_tool_keyword = /execute\-assembly\s.{0,100}\.exe\s\/ldap\:all\s\/filter\:sysvol.{0,100}netlogon.{0,100}ipc\$.{0,100}print\$/ nocase ascii wide
                        $string46_SharpShares_offensive_tool_keyword = "Hackcraft-Labs/SharpShares" nocase ascii wide
                        $string47_SharpShares_offensive_tool_keyword = "mitchmoser/SharpShares" nocase ascii wide
                        $string48_SharpShares_offensive_tool_keyword = "namespace SharpShares" nocase ascii wide
                        $string49_SharpShares_offensive_tool_keyword = /SharpShares\.csproj/ nocase ascii wide
                        $string50_SharpShares_offensive_tool_keyword = /SharpShares\.exe/ nocase ascii wide
                        $string51_SharpShares_offensive_tool_keyword = /SharpShares\.sln/ nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}