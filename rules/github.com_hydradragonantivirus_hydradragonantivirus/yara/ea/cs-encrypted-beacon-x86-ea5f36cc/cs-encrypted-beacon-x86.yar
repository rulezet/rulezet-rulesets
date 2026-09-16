rule CS_encrypted_beacon_x86 {
  meta:
    author = "Etienne Maynier tek@randhome.io"

  strings:
    $s1 = { fc e8 ?? 00 00 00 }
    $s2 = { 8b [1-3] 83 c? 04 [0-1] 8b [1-2] 31 }

  condition:
    $s1 at 0 and $s2 in (0..200) and filesize < 300000
}