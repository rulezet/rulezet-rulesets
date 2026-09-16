rule TTP_XOR_QUAD_CurrentVersionRun_6741 {
  strings:
    $key_6741 = { 34 2e [2] 10 20 [2] 3b 0c [2] 15 2e [2] 01 35 [2] 0e 2f [2] 10 32 [2] 12 33 [2] 09 35 [2] 15 32 [2] 09 1d }

  condition:
    any of them
}