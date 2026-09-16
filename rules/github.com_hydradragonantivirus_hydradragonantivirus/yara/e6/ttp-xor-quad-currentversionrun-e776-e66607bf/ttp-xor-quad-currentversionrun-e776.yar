rule TTP_XOR_QUAD_CurrentVersionRun_e776 {
  strings:
    $key_e776 = { b4 19 [2] 90 17 [2] bb 3b [2] 95 19 [2] 81 02 [2] 8e 18 [2] 90 05 [2] 92 04 [2] 89 02 [2] 95 05 [2] 89 2a }

  condition:
    any of them
}