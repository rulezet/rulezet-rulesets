rule rule_DcRat_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DcRat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DcRat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DcRat_offensive_tool_keyword = " DisableAntiSpyware 1 -Type Dword -Force -ea 0" nocase ascii wide
                        $string2_DcRat_offensive_tool_keyword = "%qwqdanchun%" nocase ascii wide
                        $string3_DcRat_offensive_tool_keyword = /\/DcRat\.git/ nocase ascii wide
                        $string4_DcRat_offensive_tool_keyword = /\/DcRat\.sln/ nocase ascii wide
                        $string5_DcRat_offensive_tool_keyword = "/DcRat/releases/download/" nocase ascii wide
                        $string6_DcRat_offensive_tool_keyword = /\/Ransomware\.exe/ nocase ascii wide
                        $string7_DcRat_offensive_tool_keyword = /\\DcRat\.sln/ nocase ascii wide
                        $string8_DcRat_offensive_tool_keyword = /\\Ransomware\.exe/ nocase ascii wide
                        $string9_DcRat_offensive_tool_keyword = /\\RemoteCamera\.dll/ nocase ascii wide
                        $string10_DcRat_offensive_tool_keyword = ">Keylogger<" nocase ascii wide
                        $string11_DcRat_offensive_tool_keyword = "001f68ac4e3ffa91b0e787586bb8382aeeb8300da5548a8802417ee6a38ff880" nocase ascii wide
                        $string12_DcRat_offensive_tool_keyword = "024d01776b9b5d42efb6115f59ec51addab5e64db969f3ec9a564f242bf702f2" nocase ascii wide
                        $string13_DcRat_offensive_tool_keyword = "0c2ddbc7ae28df7912929d7523e0116c5ba39a00c842ce23876c3c1ad5490c43" nocase ascii wide
                        $string14_DcRat_offensive_tool_keyword = "0E423DD6-FAAF-4A66-8828-6A5A5F22269B" nocase ascii wide
                        $string15_DcRat_offensive_tool_keyword = /119\.45\.104\.153\:8848/ nocase ascii wide
                        $string16_DcRat_offensive_tool_keyword = /127\.0\.0\.1\:8848/ nocase ascii wide
                        $string17_DcRat_offensive_tool_keyword = "16fef3f7f220a758a571905bad6800a58c249af4d9a0ca47eb097c07e774250f" nocase ascii wide
                        $string18_DcRat_offensive_tool_keyword = "191726b972ff700b962e92c032e0f155ab314c2edec1517e18f69c63073eb859" nocase ascii wide
                        $string19_DcRat_offensive_tool_keyword = "1b8ca67716c0928b6e8f6325dc89affc9c312353dfcaea788618c8b50337c857" nocase ascii wide
                        $string20_DcRat_offensive_tool_keyword = "21a7803ec85cae6362c0ad25529e21ca76783570b93bacbe64d0502aef852b2f" nocase ascii wide
                        $string21_DcRat_offensive_tool_keyword = "312a47c833f5ea3eb3e1f8f3a26c9bbc811a1a4b389c432715ea8f040826f65f" nocase ascii wide
                        $string22_DcRat_offensive_tool_keyword = "3379f86e6b7a13491a8aa668e567b7dfc532d79da5216fd50e3659f7ea9df372" nocase ascii wide
                        $string23_DcRat_offensive_tool_keyword = "378FC1AA-37BD-4C61-B5DE-4E45C2CDB8C9" nocase ascii wide
                        $string24_DcRat_offensive_tool_keyword = "37E20BAF-3577-4CD9-BB39-18675854E255" nocase ascii wide
                        $string25_DcRat_offensive_tool_keyword = "40C64006-EE9C-4EC8-A378-B8499142C071" nocase ascii wide
                        $string26_DcRat_offensive_tool_keyword = "419a61a91a4de08b2644a68725a73c750535ea50e525ec1aea3dacf47f2ea1ea" nocase ascii wide
                        $string27_DcRat_offensive_tool_keyword = "424B81BE-2FAC-419F-B4BC-00CCBE38491F" nocase ascii wide
                        $string28_DcRat_offensive_tool_keyword = "520411a91c6021dba0746e4520bb495db8d7c71c7b1813a95b9aae26531d493a" nocase ascii wide
                        $string29_DcRat_offensive_tool_keyword = "5D01A326-0357-4C3F-A196-3B8B866C9613" nocase ascii wide
                        $string30_DcRat_offensive_tool_keyword = "605fba81b3a049064b1bff90a6ffba00cbde7e68cdb5c22cbaa197251fc0b081" nocase ascii wide
                        $string31_DcRat_offensive_tool_keyword = "616f3a9958a29d934fd3b1362d7f10d14d1c36b1d5c144c625fc4ab525110133" nocase ascii wide
                        $string32_DcRat_offensive_tool_keyword = "619B7612-DFEA-442A-A927-D997F99C497B" nocase ascii wide
                        $string33_DcRat_offensive_tool_keyword = "66cc6913830c3720ead982e9cd43574bb3340d112521e86b4cf3c9edf627f88b" nocase ascii wide
                        $string34_DcRat_offensive_tool_keyword = "66d21568244cc3fda07d6d6c28b0bc683f18f12d4508bbe7be070b9e98989395" nocase ascii wide
                        $string35_DcRat_offensive_tool_keyword = "68115c6e039363be3b80e416ed462d97f8c763af800237b1fa183cca1180bac5" nocase ascii wide
                        $string36_DcRat_offensive_tool_keyword = "6AA4E392-AAAF-4408-B550-85863DD4BAAF" nocase ascii wide
                        $string37_DcRat_offensive_tool_keyword = "6AA4E392-AAAF-4408-B550-85863DF3BAAF" nocase ascii wide
                        $string38_DcRat_offensive_tool_keyword = "6d755e74fb426af04016752db3be2c0c17aad722173e96f5797648c1ceda2cf3" nocase ascii wide
                        $string39_DcRat_offensive_tool_keyword = "7767C300-5FD5-4A5D-9D4C-59559CCE48A3" nocase ascii wide
                        $string40_DcRat_offensive_tool_keyword = "79D3788D-683D-4799-94B7-00360F08145B" nocase ascii wide
                        $string41_DcRat_offensive_tool_keyword = "8B73C3EC-D0C4-4E0D-843A-67C81283EC5F" nocase ascii wide
                        $string42_DcRat_offensive_tool_keyword = "8BF244EB-0CA3-403E-A076-F1D77731A728" nocase ascii wide
                        $string43_DcRat_offensive_tool_keyword = "8BFC8ED2-71CC-49DC-9020-2C8199BC27B6" nocase ascii wide
                        $string44_DcRat_offensive_tool_keyword = "8DE42DA3-BE99-4E7E-A3D2-3F65E7C1ABCE" nocase ascii wide
                        $string45_DcRat_offensive_tool_keyword = "9042B543-13D1-42B3-A5B6-5CC9AD55E150" nocase ascii wide
                        $string46_DcRat_offensive_tool_keyword = "94bdfe850be6641545e52c3b0a3cbe2cb753145d02004ce8211b8468902d88ba" nocase ascii wide
                        $string47_DcRat_offensive_tool_keyword = "96dbae48dbdc89b918377d94b26393e214655b42b56044402e15046d9ecccf97" nocase ascii wide
                        $string48_DcRat_offensive_tool_keyword = "9ae914a31cb9728ac8bb4519698f992af1da69233f48eaf690e9e87cfc4445be" nocase ascii wide
                        $string49_DcRat_offensive_tool_keyword = "9D1D39D8-2387-46ED-A4A8-59D250C97F35" nocase ascii wide
                        $string50_DcRat_offensive_tool_keyword = "a18a2e9a870deb66397ea527ca071bcc74ebb7789b7aeec4a179ab13a1674a00" nocase ascii wide
                        $string51_DcRat_offensive_tool_keyword = "a2358b98f2f8c2d58f2314043c9207dae176eea11260788d7a2d67cb82f39cc9" nocase ascii wide
                        $string52_DcRat_offensive_tool_keyword = "AB6CDF36-F336-4F14-8D69-3C190B7DEC65" nocase ascii wide
                        $string53_DcRat_offensive_tool_keyword = "abb92eca9ff99f47ecad47b9ca079ba9578b5cfdd1156a3e3b09ff43a76309ed" nocase ascii wide
                        $string54_DcRat_offensive_tool_keyword = "AsyncRAT/DCRat" nocase ascii wide
                        $string55_DcRat_offensive_tool_keyword = "b2a992052d32a5b9d3702350b133289b45a8d209acd0161d9c3b0bc6fd702b3c" nocase ascii wide
                        $string56_DcRat_offensive_tool_keyword = "B5C5BDD1-568E-44F6-91FF-B26962AF9A6C" nocase ascii wide
                        $string57_DcRat_offensive_tool_keyword = "BEE88186-769A-452C-9DD9-D0E0815D92BF" nocase ascii wide
                        $string58_DcRat_offensive_tool_keyword = "C3C49F45-2589-4E04-9C50-71B6035C14AE" nocase ascii wide
                        $string59_DcRat_offensive_tool_keyword = "C3C49F45-2589-4E04-9C50-71B6035C14AE" nocase ascii wide
                        $string60_DcRat_offensive_tool_keyword = /CN\=DcRat\sServer.{0,100}OU\=qwqdanchun.{0,100}O\=DcRat\sBy\sqwqdanchun/ nocase ascii wide
                        $string61_DcRat_offensive_tool_keyword = "D640C36B-2C66-449B-A145-EB98322A67C8" nocase ascii wide
                        $string62_DcRat_offensive_tool_keyword = "DAFE686A-461B-402B-BBD7-2A2F4C87C773" nocase ascii wide
                        $string63_DcRat_offensive_tool_keyword = "DC199D9E-CF10-41DD-BBCD-98E71BA8679D" nocase ascii wide
                        $string64_DcRat_offensive_tool_keyword = "DC199D9E-CF10-41DD-BBCD-98E71BA8679D" nocase ascii wide
                        $string65_DcRat_offensive_tool_keyword = /DcRat\s\s1\.0\.7/ nocase ascii wide
                        $string66_DcRat_offensive_tool_keyword = "DcRat By qwqdanchun" nocase ascii wide
                        $string67_DcRat_offensive_tool_keyword = "DCRat Keylogger" nocase ascii wide
                        $string68_DcRat_offensive_tool_keyword = /DcRat\.7z/ nocase ascii wide
                        $string69_DcRat_offensive_tool_keyword = /DcRat\.exe/ nocase ascii wide
                        $string70_DcRat_offensive_tool_keyword = /DcRat\.zip/ nocase ascii wide
                        $string71_DcRat_offensive_tool_keyword = /DcRat_png\.png/ nocase ascii wide
                        $string72_DcRat_offensive_tool_keyword = "DCRatBuild" nocase ascii wide
                        $string73_DcRat_offensive_tool_keyword = "DCRat-Log#" nocase ascii wide
                        $string74_DcRat_offensive_tool_keyword = /DcRat\-main\.zip/ nocase ascii wide
                        $string75_DcRat_offensive_tool_keyword = "DcRatMutex_qwqdanchun" nocase ascii wide
                        $string76_DcRat_offensive_tool_keyword = "DCRatPlugin" nocase ascii wide
                        $string77_DcRat_offensive_tool_keyword = "e42d27145528616d6fe1951421989dbdaf174abe860b90bdc9321f1093593a71" nocase ascii wide
                        $string78_DcRat_offensive_tool_keyword = "EE03FAA9-C9E8-4766-BD4E-5CD54C7F13D3" nocase ascii wide
                        $string79_DcRat_offensive_tool_keyword = "EFFE3048-E904-48FD-B8C0-290E8E9290FB" nocase ascii wide
                        $string80_DcRat_offensive_tool_keyword = "f05ff84ba4bb193182883786c635cac0643b51d7046cedfc48c352ca415d348a" nocase ascii wide
                        $string81_DcRat_offensive_tool_keyword = "f15b1b50831974a8a4ac09cce5b7b9f5cc71404ee4cabe67ee2f95e890419d3c" nocase ascii wide
                        $string82_DcRat_offensive_tool_keyword = "f5986b6b5b1365e170643d4aa47939b15ea02a9d647e75a2a76bc7c0eb2de702" nocase ascii wide
                        $string83_DcRat_offensive_tool_keyword = "f67dd8a803b6a71f7e13d8d0c8d6bb07de34a401f5fc966c157fc46e1c2a557c" nocase ascii wide
                        $string84_DcRat_offensive_tool_keyword = "ffa560f9e335f64e3e5716bcf9566e2b80a9071e92f7c2da81a191026d2c3794" nocase ascii wide
                        $string85_DcRat_offensive_tool_keyword = /https\:\/\/pastebin\.com\/raw\/fevFJe98/ nocase ascii wide
                        $string86_DcRat_offensive_tool_keyword = /Keylogger\.exe/ nocase ascii wide
                        $string87_DcRat_offensive_tool_keyword = /Keylogger\.pdb/ nocase ascii wide
                        $string88_DcRat_offensive_tool_keyword = "localhost:8848" nocase ascii wide
                        $string89_DcRat_offensive_tool_keyword = "OU=qwqdanchun" nocase ascii wide
                        $string90_DcRat_offensive_tool_keyword = /Plugins\\SendFile\.dll/ nocase ascii wide
                        $string91_DcRat_offensive_tool_keyword = /Plugins\\SendMemory\.dll/ nocase ascii wide
                        $string92_DcRat_offensive_tool_keyword = "qwqdanchun" nocase ascii wide
                        $string93_DcRat_offensive_tool_keyword = "qwqdanchun/DcRat" nocase ascii wide
                        $string94_DcRat_offensive_tool_keyword = /Ransomware\.dll/ nocase ascii wide
                        $string95_DcRat_offensive_tool_keyword = /Ransomware\.pdb/ nocase ascii wide
                        $string96_DcRat_offensive_tool_keyword = /Resources\\donut\.exe/ nocase ascii wide
                        $string97_DcRat_offensive_tool_keyword = /ReverseProxy\.dll/ nocase ascii wide
                        $string98_DcRat_offensive_tool_keyword = "System' EnableSmartScreen 0 -Type Dword -Force -ea 0" nocase ascii wide
                        $string99_DcRat_offensive_tool_keyword = "Windows Defender' DisableAntiSpyware 1 -Type Dword -Force -ea 0" nocase ascii wide
                        $string100_DcRat_offensive_tool_keyword = /Windows\sDefender\sSecurity\sCenter\\\\Notifications\'\sDisableNotifications\s1\s\-Type\sDword\s\-ea\s0/ nocase ascii wide
                        $string101_DcRat_offensive_tool_keyword = /Windows\sDefender\sSecurity\sCenter\\Notifications\'\sDisableNotifications\s1\s\-Type\sDword\s\-ea\s0/ nocase ascii wide
                        $string102_DcRat_offensive_tool_keyword = "Windows Defender\" DisableAntiSpyware 1 -Type Dword -Force -ea 0" nocase ascii wide
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