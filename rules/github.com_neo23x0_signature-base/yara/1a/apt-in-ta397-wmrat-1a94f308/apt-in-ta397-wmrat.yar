rule APT_IN_TA397_wmRAT {
    meta:
        author = "Proofpoint"
        description = "track wmRAT based on socket usage, odd error handling, and reused strings"
        date = "2024-11-20"
        category = "hunting"
        malfamily = "wmRAT"
        version = "1.0"
        score = 75
        reference = "https://www.proofpoint.com/us/blog/threat-insight/hidden-plain-sight-ta397s-new-attack-chain-delivers-espionage-rats"
        hash = "3bf4bbd5564f4381820fb8da5810bd4d9718b5c80a7e8f055961007c6f30da2b"
        hash = "3e9a08972b8ec9c2e64eeb46ce1db92ae3c40bc8de48d278ba4d436fc3c8b3a4"
        hash = "40ddb4463be9d8131f363fd78e21d9de5d838a3ec4044526aea45a473d6ddd61"
        hash = "4836cb7eed0b20da50acb26472f918b180917101c026ce36074e0e879b604308"
        hash = "4e3e4d476810c95c34b6f2aa9c735f8e57e85e3b7a97c709adc5d6ee4a5f6ccc"
        hash = "5ab76cf85ade810b7ae449e3dff8a19a018174ced45d37062c86568d9b7633f9"
        hash = "811741d9df51a9f16272a64ec7eb8ff12f8f26794368b1ff4ad5d30a1f4bb42a"
        hash = "b588a423b826b57dce72c9ab58f89be2ddc710a0367ed0eed001c047d8bef32a"
        hash = "caf871247b7256945598816e9c5461d64b6bdb68a15ff9f8742ca31dc00865f8"
        id = "c5855b30-3e75-570f-b327-498dfc382159"
    strings:
        $code_sleep_loop = {
            6a 64                          ff d6                          6a 01                          e8 ?? ?? ?? ??                 83 c4 04                       3b c7              
        }
        $code_error_handling = {
            88 19                       4a                          41                          47                          4e                          85 d2                       ?? ??                       5f                          49                          5e                          b8 7a 00 07 80  
        }
        $code_socket_recv_parsing = {
                        6a 00                          b8 04 00 00 00                 2b c6                          50                             8d 0c 3e                       51                             52                             ff ??                          83 f8 ff                       ?? ??                          03 f0                          83 fe 04                     }

          $str1 = "-.-.-." ascii
          $str2 = "PATH" ascii
          $str3 = "Path=" ascii
          $str4 = "https://microsoft.com" ascii
          $str5 = "%s%ld M" ascii
          $str6 = "%s%ld K" ascii
          $str7 = "%s(%ld)" ascii
          $str8 = "RFOX" ascii
          $str9 = "1llll" ascii
          $str10 = "%d result(s)" ascii
          $str11 = "%s%ld MB" ascii
          $str12 = "%s%ld KB" ascii
          $str13 = "%.1f" ascii
          $str14 = "%02d-%02d-%d %02d:%02d" ascii
    condition:
          uint16be(0x0) == 0x4d5a and
          (2 of ($code*) or 10 of ($str*))

}