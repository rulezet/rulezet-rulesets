rule TTP_XOR_QUAD_CurrentVersionRun_3a05 {
  strings:
    $key_3a05 = { 69 6a [2] 4d 64 [2] 66 48 [2] 48 6a [2] 5c 71 [2] 53 6b [2] 4d 76 [2] 4f 77 [2] 54 71 [2] 48 76 [2] 54 59 }

  condition:
    any of them
}