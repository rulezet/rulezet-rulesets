rule TTP_XOR_QUAD_CurrentVersionRun_7041 {
  strings:
    $key_7041 = { 23 2e [2] 07 20 [2] 2c 0c [2] 02 2e [2] 16 35 [2] 19 2f [2] 07 32 [2] 05 33 [2] 1e 35 [2] 02 32 [2] 1e 1d }

  condition:
    any of them
}