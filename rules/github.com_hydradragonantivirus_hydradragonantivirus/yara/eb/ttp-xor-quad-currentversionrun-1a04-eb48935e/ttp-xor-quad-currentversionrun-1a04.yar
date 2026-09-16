rule TTP_XOR_QUAD_CurrentVersionRun_1a04 {
  strings:
    $key_1a04 = { 49 6b [2] 6d 65 [2] 46 49 [2] 68 6b [2] 7c 70 [2] 73 6a [2] 6d 77 [2] 6f 76 [2] 74 70 [2] 68 77 [2] 74 58 }

  condition:
    any of them
}