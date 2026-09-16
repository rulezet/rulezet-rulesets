rule rule_FudgeC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'FudgeC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FudgeC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_FudgeC2_offensive_tool_keyword = " FudgeC2 " nocase ascii wide
                        $string2_FudgeC2_offensive_tool_keyword = /\sPSObfucate\.py/ nocase ascii wide
                        $string3_FudgeC2_offensive_tool_keyword = /\(\(gv\s.{0,100}MDr.{0,100}\)\.NamE\[3\,11\,2\]\s\-join\s\'\'/ nocase ascii wide
                        $string4_FudgeC2_offensive_tool_keyword = /\/api\/v1\/campaign\/.{0,100}\/implants\// nocase ascii wide
                        $string5_FudgeC2_offensive_tool_keyword = /\/api\/v1\/implants\/.{0,100}\/execute/ nocase ascii wide
                        $string6_FudgeC2_offensive_tool_keyword = /\/api\/v1\/implants\/.{0,100}\/responses/ nocase ascii wide
                        $string7_FudgeC2_offensive_tool_keyword = "/c2_server/resources" nocase ascii wide
                        $string8_FudgeC2_offensive_tool_keyword = /\/campaign\/.{0,100}\/implant\/get_all/ nocase ascii wide
                        $string9_FudgeC2_offensive_tool_keyword = /\/fudge_c2\.sql/
                        $string10_FudgeC2_offensive_tool_keyword = "/FudgeC2" nocase ascii wide
                        $string11_FudgeC2_offensive_tool_keyword = "/implant/register_cmd" nocase ascii wide
                        $string12_FudgeC2_offensive_tool_keyword = /\/PSObfucate\.py/ nocase ascii wide
                        $string13_FudgeC2_offensive_tool_keyword = /\\FudgeC2/ nocase ascii wide
                        $string14_FudgeC2_offensive_tool_keyword = /\\PSObfucate\.py/ nocase ascii wide
                        $string15_FudgeC2_offensive_tool_keyword = /\|\sfOreacH\-obJeCT\s\{\(\s\[Int\]\$_\-As\[ChAr\]\)\s\}\)\)\)\\"\s1\>\s\\Windows\\Temp\\.{0,100}\s2\>\&1/ nocase ascii wide
                        $string16_FudgeC2_offensive_tool_keyword = "07019d2f4f6839056c0faf4f98e284f05c3f899f511d9766490c93d6a961fb71" nocase ascii wide
                        $string17_FudgeC2_offensive_tool_keyword = "20fdeb79608d359d60a1eb6378197f23de9cca8e77e776086335a0cea0c972f2" nocase ascii wide
                        $string18_FudgeC2_offensive_tool_keyword = "2ad1fbe554f2568cacd173a5dce1f3f87dc7e2005b1fe1dd73646a8ab9a5d1ad" nocase ascii wide
                        $string19_FudgeC2_offensive_tool_keyword = "380250752583ba94bf2f4c2b1fef9d9890615099e600b77f01fa0f15f94e3c1c" nocase ascii wide
                        $string20_FudgeC2_offensive_tool_keyword = "40b6cb38fbdefd986159c294c15a9d85f477e8f4ff2c5b2beac4c7db5a9b4772" nocase ascii wide
                        $string21_FudgeC2_offensive_tool_keyword = "6ee4bce37718d56dc3171c02415b0163d68d808342e5c0ba15851f6e48e77420" nocase ascii wide
                        $string22_FudgeC2_offensive_tool_keyword = "7582aa3ab9f635a0c3ef3522f9922e1628875fef425f81643ea7dd0ca9de68e0" nocase ascii wide
                        $string23_FudgeC2_offensive_tool_keyword = "82662ee50b98d617aa8f7859c65bb88030e6a68fe72cf4c7fef5fc94da350046" nocase ascii wide
                        $string24_FudgeC2_offensive_tool_keyword = "8a56ab0ff1d36594b9c06968b1aff8c6537dffc8e7695729cc419db4c8364d00" nocase ascii wide
                        $string25_FudgeC2_offensive_tool_keyword = "afb4d1a05a4b0b47692debfbe57946caa4bfaa2ba18b121bcfe143bf567186be" nocase ascii wide
                        $string26_FudgeC2_offensive_tool_keyword = "b887e2c6fbc2358ddae1a0b5335292faabaf628941a19b018230c0a5195201a0" nocase ascii wide
                        $string27_FudgeC2_offensive_tool_keyword = /bob\@moozle\.wtf/ nocase ascii wide
                        $string28_FudgeC2_offensive_tool_keyword = /c2_server.{0,100}\.py/ nocase ascii wide
                        $string29_FudgeC2_offensive_tool_keyword = /c2_server\.resources/ nocase ascii wide
                        $string30_FudgeC2_offensive_tool_keyword = "c55abfcbc2387e66916f27209a8c7ec2066eb3f5787ef72a7aa8945646cc3eba" nocase ascii wide
                        $string31_FudgeC2_offensive_tool_keyword = "de91f6c22eb6c8cc6da344665a046253392151bab78bf27196fec5d6d3f55b29" nocase ascii wide
                        $string32_FudgeC2_offensive_tool_keyword = /enable_persistence\.py/ nocase ascii wide
                        $string33_FudgeC2_offensive_tool_keyword = "f121ccc497eca1f3692c9ac8e8be1c1c1a4be250d05f7a23e2f71b8240da1ea5" nocase ascii wide
                        $string34_FudgeC2_offensive_tool_keyword = /FudgeC2\./ nocase ascii wide
                        $string35_FudgeC2_offensive_tool_keyword = "FudgeC2Persistence" nocase ascii wide
                        $string36_FudgeC2_offensive_tool_keyword = /FudgeC2Viewer\.py/ nocase ascii wide
                        $string37_FudgeC2_offensive_tool_keyword = "get_list_of_implant_text" nocase ascii wide
                        $string38_FudgeC2_offensive_tool_keyword = "get_obfucation_string_dict" nocase ascii wide
                        $string39_FudgeC2_offensive_tool_keyword = /get_powershell_implant_stager\(/ nocase ascii wide
                        $string40_FudgeC2_offensive_tool_keyword = /get_powershell_obf_strings\(/ nocase ascii wide
                        $string41_FudgeC2_offensive_tool_keyword = /gp\s\'HKCU\:\\Software\\Microsoft\\Windows\\CurrentVersion\\WinTrust\\Trust\sProviders\\\'\)\.State/ nocase ascii wide
                        $string42_FudgeC2_offensive_tool_keyword = /http\:\/\/127\.0\.0\.1.{0,100}\/nlaksnfaobcaowb/ nocase ascii wide
                        $string43_FudgeC2_offensive_tool_keyword = /Implant\.ImplantGenerator/ nocase ascii wide
                        $string44_FudgeC2_offensive_tool_keyword = "import EnablePersistence" nocase ascii wide
                        $string45_FudgeC2_offensive_tool_keyword = /john\@moozle\.wtf/ nocase ascii wide
                        $string46_FudgeC2_offensive_tool_keyword = /\-JoiN\'.{0,100}\[StrIng\]\:\:JOIn\(.{0,100}\s\-SPlIt.{0,100}\-sPlit.{0,100}\-SpLiT.{0,100}\-sPlIt.{0,100}\-sPLIt.{0,100}\s\|\sfOreacH\-obJeCT\s\{\(\s\[Int\]\$_\-As\[ChAr\]\)\s\}\)\)\)\\"\s1\>\s\\Windows\\Temp\\/ nocase ascii wide
                        $string47_FudgeC2_offensive_tool_keyword = /payload_encryption\.py/ nocase ascii wide
                        $string48_FudgeC2_offensive_tool_keyword = /powershell\.exe\s\-win\shidden\s\-NonI\s\-c\s\(icm\s\-scriptblock\s\(\[scriptblock\]\:\:Create\(\[System\.Text\.Encoding\]/ nocase ascii wide
                        $string49_FudgeC2_offensive_tool_keyword = "Ziconius/FudgeC2" nocase ascii wide
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