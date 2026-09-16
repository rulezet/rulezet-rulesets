rule TTP_XOR_QUAD_CurrentVersionRun_7a24 {
  strings:
    $key_7a24 = { 29 4b [2] 0d 45 [2] 26 69 [2] 08 4b [2] 1c 50 [2] 13 4a [2] 0d 57 [2] 0f 56 [2] 14 50 [2] 08 57 [2] 14 78 }

  condition:
    any of them
}