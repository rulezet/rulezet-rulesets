rule TTP_XOR_QUAD_CurrentVersionRun_e95f {
  strings:
    $key_e95f = { ba 30 [2] 9e 3e [2] b5 12 [2] 9b 30 [2] 8f 2b [2] 80 31 [2] 9e 2c [2] 9c 2d [2] 87 2b [2] 9b 2c [2] 87 03 }

  condition:
    any of them
}