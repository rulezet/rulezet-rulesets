rule TTP_XOR_QUAD_CurrentVersionRun_e963 {
  strings:
    $key_e963 = { ba 0c [2] 9e 02 [2] b5 2e [2] 9b 0c [2] 8f 17 [2] 80 0d [2] 9e 10 [2] 9c 11 [2] 87 17 [2] 9b 10 [2] 87 3f }

  condition:
    any of them
}