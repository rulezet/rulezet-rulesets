rule TTP_XOR_QUAD_CurrentVersionRun_3281 {
  strings:
    $key_3281 = { 61 ee [2] 45 e0 [2] 6e cc [2] 40 ee [2] 54 f5 [2] 5b ef [2] 45 f2 [2] 47 f3 [2] 5c f5 [2] 40 f2 [2] 5c dd }

  condition:
    any of them
}