rule TTP_XOR_QUAD_CurrentVersionRun_6280 {
  strings:
    $key_6280 = { 31 ef [2] 15 e1 [2] 3e cd [2] 10 ef [2] 04 f4 [2] 0b ee [2] 15 f3 [2] 17 f2 [2] 0c f4 [2] 10 f3 [2] 0c dc }

  condition:
    any of them
}