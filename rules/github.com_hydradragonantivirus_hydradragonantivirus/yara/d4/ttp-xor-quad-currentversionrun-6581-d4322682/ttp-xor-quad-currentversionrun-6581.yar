rule TTP_XOR_QUAD_CurrentVersionRun_6581 {
  strings:
    $key_6581 = { 36 ee [2] 12 e0 [2] 39 cc [2] 17 ee [2] 03 f5 [2] 0c ef [2] 12 f2 [2] 10 f3 [2] 0b f5 [2] 17 f2 [2] 0b dd }

  condition:
    any of them
}