rule TTP_XOR_QUAD_CurrentVersionRun_e974 {
  strings:
    $key_e974 = { ba 1b [2] 9e 15 [2] b5 39 [2] 9b 1b [2] 8f 00 [2] 80 1a [2] 9e 07 [2] 9c 06 [2] 87 00 [2] 9b 07 [2] 87 28 }

  condition:
    any of them
}