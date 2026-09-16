rule TTP_XOR_QUAD_CurrentVersionRun_6305 {
  strings:
    $key_6305 = { 30 6a [2] 14 64 [2] 3f 48 [2] 11 6a [2] 05 71 [2] 0a 6b [2] 14 76 [2] 16 77 [2] 0d 71 [2] 11 76 [2] 0d 59 }

  condition:
    any of them
}