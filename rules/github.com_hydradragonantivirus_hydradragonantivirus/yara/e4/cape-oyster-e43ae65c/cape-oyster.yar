rule CAPE_Oyster {
  meta:
    description = "Oyster Payload"
    author      = "enzok"
    id          = "29443d00-e3de-53fd-b617-df470a30e805"
    date        = "2024-05-30"
    modified    = "2024-05-30"
    reference   = "https://github.com/kevoreilly/CAPEv2"
    source_url  = "https://github.com/kevoreilly/CAPEv2/blob/28da61aec456106a39ce5a81c1257f7cce7fb270/data/yara/CAPE/Oyster.yar#L1-L19"
    license_url = "https://github.com/kevoreilly/CAPEv2/blob/28da61aec456106a39ce5a81c1257f7cce7fb270/LICENSE"
    hash        = "8bae0fa9f589cd434a689eebd7a1fde949cc09e6a65e1b56bb620998246a1650"
    logic_hash  = "23ab1518712dbce8319b87785d7ffc0c2b61de82c2bbf533ebf0aae39ec33540"
    score       = 75
    quality     = 70
    tags        = ""
    cape_type   = "Oyster Payload"

  strings:
    $start_exit   = { (05 | 00) 00 00 00 2E 96 1E A6 }
    $content_type = { F6 CE 56 F4 76 F6 96 2E 86 C6 96 36 0E 0E 86 04 5C A6 0E 9E 2A B4 2E 76 A6 2E 76 F6 C2 }
    $domain       = { 44 5C 44 76 96 86 B6 F6 26 44 34 44 }
    $id           = { 44 5C 44 64 96 44 DE }
    $ip_local     = { 44 5C 44 36 86 C6 F6 36 FA 0E 96 44 34 44 }
    $table_part_1 = { 00 80 40 C0 20 A0 60 E0 10 90 50 D0 30 B0 70 F0 08 88 48 C8 28 A8 68 }
    $table_part_2 = { 97 57 D7 37 B7 77 F7 0F 8F 4F CF 2F AF 6F EF 1F 9F 5F DF 3F BF 7F FF }
    $decode       = { 0F B6 0? 8D ?? FF 8A [2] 0F B6 80 [4] 88 04 ?? 46 0F B6 C? 0F B6 80 [4] 88 4? 01 3B F7 }

  condition:
    4 of them
}