rule TTP_XOR_QUAD_CurrentVersionRun_4280 {
  strings:
    $key_4280 = { 11 ef [2] 35 e1 [2] 1e cd [2] 30 ef [2] 24 f4 [2] 2b ee [2] 35 f3 [2] 37 f2 [2] 2c f4 [2] 30 f3 [2] 2c dc }

  condition:
    any of them
}