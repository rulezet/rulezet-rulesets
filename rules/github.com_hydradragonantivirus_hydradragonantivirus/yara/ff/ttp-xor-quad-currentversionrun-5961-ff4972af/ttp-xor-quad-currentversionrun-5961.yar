rule TTP_XOR_QUAD_CurrentVersionRun_5961 {
  strings:
    $key_5961 = { 0a 0e [2] 2e 00 [2] 05 2c [2] 2b 0e [2] 3f 15 [2] 30 0f [2] 2e 12 [2] 2c 13 [2] 37 15 [2] 2b 12 [2] 37 3d }

  condition:
    any of them
}