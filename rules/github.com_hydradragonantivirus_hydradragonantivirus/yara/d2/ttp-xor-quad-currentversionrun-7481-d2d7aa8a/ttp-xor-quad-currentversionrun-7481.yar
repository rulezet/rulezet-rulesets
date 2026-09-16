rule TTP_XOR_QUAD_CurrentVersionRun_7481 {
  strings:
    $key_7481 = { 27 ee [2] 03 e0 [2] 28 cc [2] 06 ee [2] 12 f5 [2] 1d ef [2] 03 f2 [2] 01 f3 [2] 1a f5 [2] 06 f2 [2] 1a dd }

  condition:
    any of them
}