rule TTP_XOR_QUAD_CurrentVersionRun_e96e {
  strings:
    $key_e96e = { ba 01 [2] 9e 0f [2] b5 23 [2] 9b 01 [2] 8f 1a [2] 80 00 [2] 9e 1d [2] 9c 1c [2] 87 1a [2] 9b 1d [2] 87 32 }

  condition:
    any of them
}