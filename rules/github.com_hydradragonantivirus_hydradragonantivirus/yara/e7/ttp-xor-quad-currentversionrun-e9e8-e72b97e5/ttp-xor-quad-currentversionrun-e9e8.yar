rule TTP_XOR_QUAD_CurrentVersionRun_e9e8 {
  strings:
    $key_e9e8 = { ba 87 [2] 9e 89 [2] b5 a5 [2] 9b 87 [2] 8f 9c [2] 80 86 [2] 9e 9b [2] 9c 9a [2] 87 9c [2] 9b 9b [2] 87 b4 }

  condition:
    any of them
}