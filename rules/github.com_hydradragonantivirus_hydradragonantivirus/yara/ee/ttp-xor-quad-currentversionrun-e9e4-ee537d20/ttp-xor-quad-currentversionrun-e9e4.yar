rule TTP_XOR_QUAD_CurrentVersionRun_e9e4 {
  strings:
    $key_e9e4 = { ba 8b [2] 9e 85 [2] b5 a9 [2] 9b 8b [2] 8f 90 [2] 80 8a [2] 9e 97 [2] 9c 96 [2] 87 90 [2] 9b 97 [2] 87 b8 }

  condition:
    any of them
}