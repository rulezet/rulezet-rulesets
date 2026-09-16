rule TTP_XOR_QUAD_CurrentVersionRun_e973 {
  strings:
    $key_e973 = { ba 1c [2] 9e 12 [2] b5 3e [2] 9b 1c [2] 8f 07 [2] 80 1d [2] 9e 00 [2] 9c 01 [2] 87 07 [2] 9b 00 [2] 87 2f }

  condition:
    any of them
}