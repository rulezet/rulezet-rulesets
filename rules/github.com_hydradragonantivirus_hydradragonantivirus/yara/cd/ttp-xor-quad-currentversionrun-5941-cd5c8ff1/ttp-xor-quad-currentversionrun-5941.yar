rule TTP_XOR_QUAD_CurrentVersionRun_5941 {
  strings:
    $key_5941 = { 0a 2e [2] 2e 20 [2] 05 0c [2] 2b 2e [2] 3f 35 [2] 30 2f [2] 2e 32 [2] 2c 33 [2] 37 35 [2] 2b 32 [2] 37 1d }

  condition:
    any of them
}