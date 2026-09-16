rule TTP_XOR_QUAD_CurrentVersionRun_6f04 {
  strings:
    $key_6f04 = { 3c 6b [2] 18 65 [2] 33 49 [2] 1d 6b [2] 09 70 [2] 06 6a [2] 18 77 [2] 1a 76 [2] 01 70 [2] 1d 77 [2] 01 58 }

  condition:
    any of them
}