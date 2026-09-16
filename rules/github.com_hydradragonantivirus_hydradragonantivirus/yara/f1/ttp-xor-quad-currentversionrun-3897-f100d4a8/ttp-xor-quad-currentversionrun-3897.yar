rule TTP_XOR_QUAD_CurrentVersionRun_3897 {
  strings:
    $key_3897 = { 6b f8 [2] 4f f6 [2] 64 da [2] 4a f8 [2] 5e e3 [2] 51 f9 [2] 4f e4 [2] 4d e5 [2] 56 e3 [2] 4a e4 [2] 56 cb }

  condition:
    any of them
}