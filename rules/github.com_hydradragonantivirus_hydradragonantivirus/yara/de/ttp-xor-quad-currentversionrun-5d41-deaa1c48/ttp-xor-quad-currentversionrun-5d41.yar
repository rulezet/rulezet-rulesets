rule TTP_XOR_QUAD_CurrentVersionRun_5d41 {
  strings:
    $key_5d41 = { 0e 2e [2] 2a 20 [2] 01 0c [2] 2f 2e [2] 3b 35 [2] 34 2f [2] 2a 32 [2] 28 33 [2] 33 35 [2] 2f 32 [2] 33 1d }

  condition:
    any of them
}