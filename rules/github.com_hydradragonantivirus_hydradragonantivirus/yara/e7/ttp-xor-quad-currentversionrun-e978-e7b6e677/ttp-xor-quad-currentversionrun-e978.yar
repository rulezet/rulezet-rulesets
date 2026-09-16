rule TTP_XOR_QUAD_CurrentVersionRun_e978 {
  strings:
    $key_e978 = { ba 17 [2] 9e 19 [2] b5 35 [2] 9b 17 [2] 8f 0c [2] 80 16 [2] 9e 0b [2] 9c 0a [2] 87 0c [2] 9b 0b [2] 87 24 }

  condition:
    any of them
}