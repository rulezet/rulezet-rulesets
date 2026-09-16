rule rule_Eventlogedit_evtx__Evolution_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Eventlogedit-evtx--Evolution' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Eventlogedit-evtx--Evolution"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Eventlogedit_evtx__Evolution_offensive_tool_keyword = /\/Eventlogedit\-evtx\-\-Evolution\.git/ nocase ascii wide
                        $string2_Eventlogedit_evtx__Evolution_offensive_tool_keyword = /\\DeleteRecordbyGetHandle\.cpp/ nocase ascii wide
                        $string3_Eventlogedit_evtx__Evolution_offensive_tool_keyword = /\\DeleteRecordbyGetHandle\.exe/ nocase ascii wide
                        $string4_Eventlogedit_evtx__Evolution_offensive_tool_keyword = /\\DeleteRecordbyGetHandleEx\.cpp/ nocase ascii wide
                        $string5_Eventlogedit_evtx__Evolution_offensive_tool_keyword = /\\DeleteRecordbyTerminateProcess\.cpp/ nocase ascii wide
                        $string6_Eventlogedit_evtx__Evolution_offensive_tool_keyword = /\\DeleteRecordbyTerminateProcess\.exe/ nocase ascii wide
                        $string7_Eventlogedit_evtx__Evolution_offensive_tool_keyword = /\\DeleteRecordbyTerminateProcessEx\.cpp/ nocase ascii wide
                        $string8_Eventlogedit_evtx__Evolution_offensive_tool_keyword = /\\DeleteRecordbyTerminateProcessEx\.exe/ nocase ascii wide
                        $string9_Eventlogedit_evtx__Evolution_offensive_tool_keyword = /\\DeleteRecord\-EvtExportLog\.cpp/ nocase ascii wide
                        $string10_Eventlogedit_evtx__Evolution_offensive_tool_keyword = /\\DeleteRecord\-EvtExportLog\.exe/ nocase ascii wide
                        $string11_Eventlogedit_evtx__Evolution_offensive_tool_keyword = /\\DeleteRecordofFile\.exe/ nocase ascii wide
                        $string12_Eventlogedit_evtx__Evolution_offensive_tool_keyword = /\\DeleteRecordofFileEx\.exe/ nocase ascii wide
                        $string13_Eventlogedit_evtx__Evolution_offensive_tool_keyword = /\\Dll\-EvtExportLog\.cpp/ nocase ascii wide
                        $string14_Eventlogedit_evtx__Evolution_offensive_tool_keyword = /\\Dll\-EvtExportLog\.dll/ nocase ascii wide
                        $string15_Eventlogedit_evtx__Evolution_offensive_tool_keyword = /\\Dll\-rewriting\.cpp/ nocase ascii wide
                        $string16_Eventlogedit_evtx__Evolution_offensive_tool_keyword = /\\Dll\-rewriting\.dll/ nocase ascii wide
                        $string17_Eventlogedit_evtx__Evolution_offensive_tool_keyword = /\\Eventlogedit\-evtx\-\-Evolution\-master\-v1\.1/ nocase ascii wide
                        $string18_Eventlogedit_evtx__Evolution_offensive_tool_keyword = /\\Loader\-EvtExportLog\.cpp/ nocase ascii wide
                        $string19_Eventlogedit_evtx__Evolution_offensive_tool_keyword = /\\Loader\-EvtExportLog\.exe/ nocase ascii wide
                        $string20_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "0f6c95ac01cddb461aef1267d60ded9c723aaed9c64cb4507df5cd94e9a1782c" nocase ascii wide
                        $string21_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "1b1b954cd8593a3d62bfc75524952c11499f269510fd1039a9ec5fa9655b92a7" nocase ascii wide
                        $string22_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "2257aeb5d063b08394d05286d7d9adfb5850571ea4ffff9ec3d06eb5af75f0e9" nocase ascii wide
                        $string23_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "319895b096e8bd0d034246c8b7f11b067fc54831451f14d77d04f9b9c50818bc" nocase ascii wide
                        $string24_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "32221248ee8f748433e89431976294ffa3a62c500e364699cb67fa8471b9c0be" nocase ascii wide
                        $string25_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "37a95e2ef3089da0c4c732b45cd9aee36b5a0a0709abf4dd1a739a24f8d08c61" nocase ascii wide
                        $string26_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "3d136d26be0a8879daf18698d9b1e19a4c7a3ef095568a03d4b7a9e0f270034c" nocase ascii wide
                        $string27_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "3gstudent/Eventlogedit-evtx--Evolution" nocase ascii wide
                        $string28_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "44c00be47b5171d3edde7649c556efd366d1343665be0610c62941091b081e40" nocase ascii wide
                        $string29_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "52ff6af0c995ccf66fcd0379f1236578a907768eac72bf659cd7c567c5bb70b2" nocase ascii wide
                        $string30_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "59875ad922a551d9831d93e54c731399803a814f95a766ef920aef69441564f9" nocase ascii wide
                        $string31_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "6d4393769a27fd089c9c9f9a52f59e8275397c1c3b8df8ca7c972a3246cb9392" nocase ascii wide
                        $string32_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "8401c11807fda1838139211517f0aee7ed7198e237b7fd87deceb23e092f1552" nocase ascii wide
                        $string33_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "8886b069180a096d54b6d6555aa3a5b8c44359eb858a072f6e34943fe40b1fdf" nocase ascii wide
                        $string34_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "8df104dd0a3a4290bbc33eb8a98a771a8f391120f3014ccb9f2cf496561cccd4" nocase ascii wide
                        $string35_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "9437e734cd6f37285d60b1d1c33de982d032cd7dea8a0349354c296e9ba46fbc" nocase ascii wide
                        $string36_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "98b4b0f773391657d762c06de6aa9710e7f56d64a0fd720d1a68e733a8173062" nocase ascii wide
                        $string37_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "a516e0818b79c222bdc64dcc4f94733ec0678a1dd16a6502d2fc2c722142a5e5" nocase ascii wide
                        $string38_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "ad953b6731c27ada2c6c7dfd14aca6f46218b962db4272a5c042e4259dacb2e3" nocase ascii wide
                        $string39_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "b540f94a9f462bc217673faf2d247cb4b9b3eb44ae3307890dc6cda3aa3e5bb2" nocase ascii wide
                        $string40_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "b7aac417714cff0bd0a03475b7ff00ccdf5480bc463c14d407b9ed8bc8ffcc02" nocase ascii wide
                        $string41_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "c5f7d585b6535e971c693b57c8a468e5cd9408da09bc91e6dabd8d3b65fe2ba2" nocase ascii wide
                        $string42_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "c9a67da63c7f2a139df34098d0e74e225b67ed7acc93b18ff23601ce291ab00b" nocase ascii wide
                        $string43_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "cc7f5f00092e920726e25cf3c47cbf36727e87aba7b4204408b9a44b67816b08" nocase ascii wide
                        $string44_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "d66e5c655b6ecf6108ebdba4c14b669f8b9dc4c18cfd8eb309878ad936fdc2b9" nocase ascii wide
                        $string45_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "Delete the eventlog by rewriting the evtx file" nocase ascii wide
                        $string46_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "Delete the eventlog by using WinAPI EvtExportLog" nocase ascii wide
                        $string47_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "e090e512d904f56de3f88655cd846ef48fb4d6ed5fedd1f452225c1917f5e352" nocase ascii wide
                        $string48_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "e3c611553b1544143dd625f75395d57ed0ccc260dc0e6d0204b512a492957050" nocase ascii wide
                        $string49_Eventlogedit_evtx__Evolution_offensive_tool_keyword = "ea10050aaa6ca06ddceb1e7e47205bf8a59b4f01918dcd7e22cca7aad5613d13" nocase ascii wide
                        $string50_Eventlogedit_evtx__Evolution_offensive_tool_keyword = /Eventlogedit\-evtx\-\-Evolution\-master\-v1\.1\.zip/ nocase ascii wide

    condition:
        any of them
}