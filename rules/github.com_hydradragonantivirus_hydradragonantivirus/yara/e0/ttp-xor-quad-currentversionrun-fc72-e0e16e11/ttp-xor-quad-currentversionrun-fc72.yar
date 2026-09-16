rule TTP_XOR_QUAD_CurrentVersionRun_fc72 {
  strings:
    $key_fc72 = { af 1d [2] 8b 13 [2] a0 3f [2] 8e 1d [2] 9a 06 [2] 95 1c [2] 8b 01 [2] 89 00 [2] 92 06 [2] 8e 01 [2] 92 2e }

  condition:
    any of them
}