rule TTP_XOR_QUAD_CurrentVersionRun_e9e5 {
  strings:
    $key_e9e5 = { ba 8a [2] 9e 84 [2] b5 a8 [2] 9b 8a [2] 8f 91 [2] 80 8b [2] 9e 96 [2] 9c 97 [2] 87 91 [2] 9b 96 [2] 87 b9 }

  condition:
    any of them
}