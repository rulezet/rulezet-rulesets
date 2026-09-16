rule TTP_XOR_QUAD_CurrentVersionRun_7a05 {
  strings:
    $key_7a05 = { 29 6a [2] 0d 64 [2] 26 48 [2] 08 6a [2] 1c 71 [2] 13 6b [2] 0d 76 [2] 0f 77 [2] 14 71 [2] 08 76 [2] 14 59 }

  condition:
    any of them
}