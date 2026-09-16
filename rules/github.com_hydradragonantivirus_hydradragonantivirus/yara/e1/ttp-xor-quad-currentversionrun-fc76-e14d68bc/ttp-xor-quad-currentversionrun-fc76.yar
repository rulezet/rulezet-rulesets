rule TTP_XOR_QUAD_CurrentVersionRun_fc76 {
  strings:
    $key_fc76 = { af 19 [2] 8b 17 [2] a0 3b [2] 8e 19 [2] 9a 02 [2] 95 18 [2] 8b 05 [2] 89 04 [2] 92 02 [2] 8e 05 [2] 92 2a }

  condition:
    any of them
}