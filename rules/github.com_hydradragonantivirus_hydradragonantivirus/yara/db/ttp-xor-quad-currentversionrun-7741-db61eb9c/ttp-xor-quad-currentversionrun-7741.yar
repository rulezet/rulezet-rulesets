rule TTP_XOR_QUAD_CurrentVersionRun_7741 {
  strings:
    $key_7741 = { 24 2e [2] 00 20 [2] 2b 0c [2] 05 2e [2] 11 35 [2] 1e 2f [2] 00 32 [2] 02 33 [2] 19 35 [2] 05 32 [2] 19 1d }

  condition:
    any of them
}