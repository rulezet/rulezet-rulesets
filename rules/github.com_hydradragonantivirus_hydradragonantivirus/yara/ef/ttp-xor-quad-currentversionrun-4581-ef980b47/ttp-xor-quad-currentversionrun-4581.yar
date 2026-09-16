rule TTP_XOR_QUAD_CurrentVersionRun_4581 {
  strings:
    $key_4581 = { 16 ee [2] 32 e0 [2] 19 cc [2] 37 ee [2] 23 f5 [2] 2c ef [2] 32 f2 [2] 30 f3 [2] 2b f5 [2] 37 f2 [2] 2b dd }

  condition:
    any of them
}