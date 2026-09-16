rule TTP_XOR_QUAD_CurrentVersionRun_4071 {
  strings:
    $key_4071 = { 13 1e [2] 37 10 [2] 1c 3c [2] 32 1e [2] 26 05 [2] 29 1f [2] 37 02 [2] 35 03 [2] 2e 05 [2] 32 02 [2] 2e 2d }

  condition:
    any of them
}