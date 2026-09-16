rule TTP_XOR_QUAD_CurrentVersionRun_0164 {
  strings:
    $key_0164 = { 52 0b [2] 76 05 [2] 5d 29 [2] 73 0b [2] 67 10 [2] 68 0a [2] 76 17 [2] 74 16 [2] 6f 10 [2] 73 17 [2] 6f 38 }

  condition:
    any of them
}