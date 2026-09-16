rule TTP_XOR_QUAD_CurrentVersionRun_0154 {
  strings:
    $key_0154 = { 52 3b [2] 76 35 [2] 5d 19 [2] 73 3b [2] 67 20 [2] 68 3a [2] 76 27 [2] 74 26 [2] 6f 20 [2] 73 27 [2] 6f 08 }

  condition:
    any of them
}