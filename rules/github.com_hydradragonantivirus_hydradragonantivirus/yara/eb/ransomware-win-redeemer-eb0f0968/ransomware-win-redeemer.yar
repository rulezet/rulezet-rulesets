rule ransomware_win_redeemer {
  meta:
    version        = "1.0"
    description    = "Finds Redeemer samples based on characteristic strings"
    author         = "Sekoia.io"
    creation_date  = "2022-12-09"
    id             = "ef94c1b0-d292-4fae-9801-4860e7347745"
    classification = "TLP:CLEAR"

  strings:
    $str0 = "RedeemerMutex" ascii
    $str1 = "SOFTWARE\\Redeemer" ascii
    $str2 = "-----BEGIN REDEEMER PUBLIC KEY-----" ascii
    $str3 = "dnNzYWRtaW4gZGVsZXRlIHNoYWRvd3MgL0FsbCAvUXVpZXQ=" ascii      $str4 = "d2V2dHV0aWwgY2xlYXItbG9nIEFwcGxpY2F0aW9u" ascii      $str5 = "d2JhZG1pbiBkZWxldGUgc3lzdGVtc3RhdGViYWNrdXAgLWRlbGV0ZW9sZGVzdCAtcXVpZXQ=" ascii      $str6 = "YXNzb2MgLnJlZGVlbT1yZWRlZW1lcg==" ascii      $str7 = "UmVkZWVtZXIgUmFuc29td2FyZSAtIFlvdXIgRGF0YSBJcyBFbmNyeXB0ZWQ=" ascii      $str8 = "redeemer\\DefaultIcon" wide
    $str9 = "\\Redeemer.sys" wide

  condition:
    uint16(0) == 0x5A4D and 2 of them
}