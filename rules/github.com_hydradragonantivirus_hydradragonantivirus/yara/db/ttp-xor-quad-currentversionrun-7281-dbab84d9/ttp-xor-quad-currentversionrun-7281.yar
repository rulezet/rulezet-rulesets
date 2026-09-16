rule TTP_XOR_QUAD_CurrentVersionRun_7281 {
  strings:
    $key_7281 = { 21 ee [2] 05 e0 [2] 2e cc [2] 00 ee [2] 14 f5 [2] 1b ef [2] 05 f2 [2] 07 f3 [2] 1c f5 [2] 00 f2 [2] 1c dd }

  condition:
    any of them
}