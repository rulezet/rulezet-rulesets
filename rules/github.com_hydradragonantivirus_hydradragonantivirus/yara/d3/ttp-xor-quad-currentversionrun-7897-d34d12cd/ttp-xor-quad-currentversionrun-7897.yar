rule TTP_XOR_QUAD_CurrentVersionRun_7897 {
  strings:
    $key_7897 = { 2b f8 [2] 0f f6 [2] 24 da [2] 0a f8 [2] 1e e3 [2] 11 f9 [2] 0f e4 [2] 0d e5 [2] 16 e3 [2] 0a e4 [2] 16 cb }

  condition:
    any of them
}