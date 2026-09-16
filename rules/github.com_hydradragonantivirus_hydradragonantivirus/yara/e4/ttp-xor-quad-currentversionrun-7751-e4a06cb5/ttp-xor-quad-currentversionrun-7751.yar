rule TTP_XOR_QUAD_CurrentVersionRun_7751 {
  strings:
    $key_7751 = { 24 3e [2] 00 30 [2] 2b 1c [2] 05 3e [2] 11 25 [2] 1e 3f [2] 00 22 [2] 02 23 [2] 19 25 [2] 05 22 [2] 19 0d }

  condition:
    any of them
}