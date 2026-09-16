rule TTP_XOR_QUAD_CurrentVersionRun_5004 {
  strings:
    $key_5004 = { 03 6b [2] 27 65 [2] 0c 49 [2] 22 6b [2] 36 70 [2] 39 6a [2] 27 77 [2] 25 76 [2] 3e 70 [2] 22 77 [2] 3e 58 }

  condition:
    any of them
}