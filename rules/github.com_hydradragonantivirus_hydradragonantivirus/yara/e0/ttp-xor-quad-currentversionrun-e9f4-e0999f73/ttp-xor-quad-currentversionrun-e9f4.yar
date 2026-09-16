rule TTP_XOR_QUAD_CurrentVersionRun_e9f4 {
  strings:
    $key_e9f4 = { ba 9b [2] 9e 95 [2] b5 b9 [2] 9b 9b [2] 8f 80 [2] 80 9a [2] 9e 87 [2] 9c 86 [2] 87 80 [2] 9b 87 [2] 87 a8 }

  condition:
    any of them
}