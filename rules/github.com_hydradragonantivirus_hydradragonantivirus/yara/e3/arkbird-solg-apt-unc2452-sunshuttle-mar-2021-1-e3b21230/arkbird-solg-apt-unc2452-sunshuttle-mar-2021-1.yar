rule ARKBIRD_SOLG_APT_UNC2452_Sunshuttle_Mar_2021_1: FILE {
  meta:
    description = "Detect Sunshuttle implant used by UNC2452 group"
    author      = "Arkbird_SOLG"
    id          = "faa07d19-4c61-554d-a6b1-ab7cb0919ec0"
    date        = "2021-03-06"
    modified    = "2021-03-06"
    reference   = "https://twitter.com/Arkbird_SOLG/status/1367570764468224010"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-03-06/UNC2452/APT_UNC2452_sunshuttle_Mar_2021_1.yar#L1-L31"
    license_url = "N/A"
    logic_hash  = "368487f1716aaa5c10e19a428649d6706b3f45c53853e6729752dc41fc97bc38"
    score       = 75
    quality     = 63
    tags        = "FILE"
    hash1       = "611458206837560511cb007ab5eeb57047025c2edc0643184561a6bf451e8c2c"
    hash2       = "b9a2c986b6ad1eb4cfb0303baede906936fe96396f3cf490b0984a4798d741d8"
    hash3       = "bbd16685917b9b35c7480d5711193c1cd0e4e7ccb0f2bf1fd584c0aebca5ae4c"

  strings:
    $s1  = "Go build ID: \"9YrBjkkXFykbGQrmV2KI/AHDizWQaM8G8J7kVK2Ve/FUt_kkSVlx26InFVaypw/luZAT5UnUi4dJeknskUn\""
    $s2  = "Go build ID: \"qofIkvbls1irO6xhjAcZ/jIiqApp1Vo9rOS-DjeNu/bPun3N5tIBXKPtNysHOQ/ARSrcek5hQG8YIVnMu7T\""
    $s3  = "os/exec.(*Cmd).Run"
    $s4  = "main.request_session_key" fullword ascii
    $s5  = "main.wget_file" fullword ascii
    $s6  = "main.GetMD5Hash" fullword ascii
    $s7  = "main.beaconing" fullword ascii
    $s8  = "main.resolve_command" fullword ascii
    $s9  = "main.send_file_part" fullword ascii
    $s10 = "main.retrieve_session_key" fullword ascii
    $s11 = "main.send_command_result" fullword ascii
    $s12 = "c8:27:cc:c2:37:5a"
    $s13 = "-----BEGIN"
    $s14 = "-----END"

  condition:
    uint16(0) == 0x5a4d and filesize > 800KB and 12 of them
}