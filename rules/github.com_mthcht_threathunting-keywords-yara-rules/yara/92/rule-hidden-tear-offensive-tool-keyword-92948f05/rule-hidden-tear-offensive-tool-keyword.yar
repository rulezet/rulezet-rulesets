rule rule_hidden_tear_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'hidden-tear' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hidden-tear"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_hidden_tear_offensive_tool_keyword = "\"dsdoskdosk837928hduijfh\"" nocase ascii wide
                        $string2_hidden_tear_offensive_tool_keyword = /\/hidden\-tear\.exe/ nocase ascii wide
                        $string3_hidden_tear_offensive_tool_keyword = /\/hidden\-tear\.git/ nocase ascii wide
                        $string4_hidden_tear_offensive_tool_keyword = /\/HiddenTear\.zip/ nocase ascii wide
                        $string5_hidden_tear_offensive_tool_keyword = /\/hidden\-tear\/write\.php\?info\=/ nocase ascii wide
                        $string6_hidden_tear_offensive_tool_keyword = /\/hidden\-tear\-remake\.git/ nocase ascii wide
                        $string7_hidden_tear_offensive_tool_keyword = /\\hidden_tear\.Form1\.resources/ nocase ascii wide
                        $string8_hidden_tear_offensive_tool_keyword = /\\hidden\-tear\.csproj/ nocase ascii wide
                        $string9_hidden_tear_offensive_tool_keyword = /\\hidden\-tear\.exe/ nocase ascii wide
                        $string10_hidden_tear_offensive_tool_keyword = /\\hidden\-tear\.pdb/ nocase ascii wide
                        $string11_hidden_tear_offensive_tool_keyword = /\\hidden\-tear\.sln/ nocase ascii wide
                        $string12_hidden_tear_offensive_tool_keyword = /\\hidden\-tear\.vshost\.exe/ nocase ascii wide
                        $string13_hidden_tear_offensive_tool_keyword = /\\HiddenTear\.zip/ nocase ascii wide
                        $string14_hidden_tear_offensive_tool_keyword = /\\hidden\-tear\-remake\\/ nocase ascii wide
                        $string15_hidden_tear_offensive_tool_keyword = ">hidden_tear_decrypter<" nocase ascii wide
                        $string16_hidden_tear_offensive_tool_keyword = /\>hidden\-tear\.exe\</ nocase ascii wide
                        $string17_hidden_tear_offensive_tool_keyword = ">hidden-tear<" nocase ascii wide
                        $string18_hidden_tear_offensive_tool_keyword = "07dd043bc4e5ef2651ac9a1b4e5b849ce2e3dd6e3ca593a48625b568cfff924b" nocase ascii wide
                        $string19_hidden_tear_offensive_tool_keyword = "099923b629ff4309a579a66eaa857de4e5d5caa093b6226ee7c491742d9168e9" nocase ascii wide
                        $string20_hidden_tear_offensive_tool_keyword = "0xbdg/hidden-tear-remake" nocase ascii wide
                        $string21_hidden_tear_offensive_tool_keyword = "19804c0341ec2408b025626ac9259438f9c403104f155eedfa9b2395d85490b3" nocase ascii wide
                        $string22_hidden_tear_offensive_tool_keyword = "2949af17b0dd766d99667bcc09646f484583cd7dcc0216fd626b517b47a91a73" nocase ascii wide
                        $string23_hidden_tear_offensive_tool_keyword = "3ce3579ba41d1ccab336da1f8768a257142c3f6eee0e8daac2605065e3a43234" nocase ascii wide
                        $string24_hidden_tear_offensive_tool_keyword = "4182eca7aebb0a2cddd4d7c069fec1295f3fcf3a48d1c2e7f690a7be6e8324e2" nocase ascii wide
                        $string25_hidden_tear_offensive_tool_keyword = "5664867318d287a388546bbb20c8d7fb7d24680a97209f4f29d25b9cb9da24ec" nocase ascii wide
                        $string26_hidden_tear_offensive_tool_keyword = "66012c3a70e772908a9e8571665562fad55a04447452b751719a80d20ebf83e7" nocase ascii wide
                        $string27_hidden_tear_offensive_tool_keyword = "660309440ef382c2966a9186161e0777d4e4fbd7b0acce8ef040e43609513282" nocase ascii wide
                        $string28_hidden_tear_offensive_tool_keyword = "79f30574ad34a49673425cb37cd038106cc9fb49615cd6a2d05986e0c7c010e2" nocase ascii wide
                        $string29_hidden_tear_offensive_tool_keyword = "7a1d50f5e8827f2b2f920811f966be5358f0a24fa52301852b32ba94146a7be6" nocase ascii wide
                        $string30_hidden_tear_offensive_tool_keyword = "82C19CBA-E318-4BB3-A408-5005EA083EC5" nocase ascii wide
                        $string31_hidden_tear_offensive_tool_keyword = "8e8f868c283b165b0ccf0da8c85458d10d785bc872007be2ee33cb756a741ceb" nocase ascii wide
                        $string32_hidden_tear_offensive_tool_keyword = "a4045cfd2b84fce0d46096b6dc9f82f8745907b5828a96b522da42cbd5f5563f" nocase ascii wide
                        $string33_hidden_tear_offensive_tool_keyword = /All\syour\simportant\sfiles\s\(documents\,\sphotos\,\svideos\,\sdatabases\,\sand\sother\sfiles\)\shave\sbeen\sencrypted\susing\sa\sstrong\sencryption\salgorithm\.\sYou\sare\sunable\sto\saccess\sthese\sfiles\sas\sthey\shave\sbeen\stransformed\sinto\sunreadable\scontent/ nocase ascii wide
                        $string34_hidden_tear_offensive_tool_keyword = "b12ada1dcac400d11a462a62ec3957adbdb82a4bfb04cef08533281bdbf286a5" nocase ascii wide
                        $string35_hidden_tear_offensive_tool_keyword = "B138FFBA-1076-4B58-8A98-67B34E8A7C5C" nocase ascii wide
                        $string36_hidden_tear_offensive_tool_keyword = "c5b452ef4e7c5a5cd045419c94244148563d168a7d682baa622d113466e4a3ae" nocase ascii wide
                        $string37_hidden_tear_offensive_tool_keyword = "cd4f7b330f78c41ce8f119e1bd4c14a2da54ed3f2b1482c18247acea6411d2a4" nocase ascii wide
                        $string38_hidden_tear_offensive_tool_keyword = /Cryptolocker\-1\.0\.0\.rar/ nocase ascii wide
                        $string39_hidden_tear_offensive_tool_keyword = "d7af38341aa0abbe61415eed66c9df434b901425b5c2acfe01b9619530c826a2" nocase ascii wide
                        $string40_hidden_tear_offensive_tool_keyword = "e4cfb74b6002861358363025a31d0dd682a1cb67149d6608825f63fe46d01c38" nocase ascii wide
                        $string41_hidden_tear_offensive_tool_keyword = "fb20b0f19aab92962085d0d2fbf21ccc142620e12b6cccc20f28387b6c379d65" nocase ascii wide
                        $string42_hidden_tear_offensive_tool_keyword = "Files has been encrypted with hidden tear" nocase ascii wide
                        $string43_hidden_tear_offensive_tool_keyword = "goliate/hidden-tear" nocase ascii wide
                        $string44_hidden_tear_offensive_tool_keyword = /hidden_tear_decrypter\.Properties\.Resources/ nocase ascii wide
                        $string45_hidden_tear_offensive_tool_keyword = /hidden\-tear\-1\-master\.zip/ nocase ascii wide
                        $string46_hidden_tear_offensive_tool_keyword = /hidden\-tear\-decrypter\.csproj/ nocase ascii wide
                        $string47_hidden_tear_offensive_tool_keyword = /hidden\-tear\-decrypter\.exe/ nocase ascii wide
                        $string48_hidden_tear_offensive_tool_keyword = /hidden\-tear\-decrypter\.pdb/ nocase ascii wide
                        $string49_hidden_tear_offensive_tool_keyword = /hidden\-tear\-master\.zip/ nocase ascii wide
                        $string50_hidden_tear_offensive_tool_keyword = /hidden\-tear\-remake\.zip/ nocase ascii wide
                        $string51_hidden_tear_offensive_tool_keyword = /http\:\/\/utkusen\.com\/hidden\-tear\// nocase ascii wide
                        $string52_hidden_tear_offensive_tool_keyword = "namespace hidden_tear" nocase ascii wide
                        $string53_hidden_tear_offensive_tool_keyword = /namespace\shidden_tear\.Tools\,/ nocase ascii wide
                        $string54_hidden_tear_offensive_tool_keyword = /New\sVictim\s\[\{Environment\.UserName\}/ nocase ascii wide
                        $string55_hidden_tear_offensive_tool_keyword = "Send me some bitcoins or kebab" nocase ascii wide
                        $string56_hidden_tear_offensive_tool_keyword = /using\shidden_tear\.Tools/ nocase ascii wide
                        $string57_hidden_tear_offensive_tool_keyword = /Your\sFiles\sHave\sBeen\sEncrypted\!.{0,100}What\sHappened\sto\sMy\sFiles\?/ nocase ascii wide
                        $string58_hidden_tear_offensive_tool_keyword = "Your files have been infected and stolen" nocase ascii wide
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