rule TTP_XOR_QUAD_CurrentVersionRun_6897 {
  strings:
    $key_6897 = { 3b f8 [2] 1f f6 [2] 34 da [2] 1a f8 [2] 0e e3 [2] 01 f9 [2] 1f e4 [2] 1d e5 [2] 06 e3 [2] 1a e4 [2] 06 cb }

  condition:
    any of them
}