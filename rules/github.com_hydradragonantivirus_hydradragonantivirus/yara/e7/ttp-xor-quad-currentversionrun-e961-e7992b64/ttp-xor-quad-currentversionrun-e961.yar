rule TTP_XOR_QUAD_CurrentVersionRun_e961 {
  strings:
    $key_e961 = { ba 0e [2] 9e 00 [2] b5 2c [2] 9b 0e [2] 8f 15 [2] 80 0f [2] 9e 12 [2] 9c 13 [2] 87 15 [2] 9b 12 [2] 87 3d }

  condition:
    any of them
}