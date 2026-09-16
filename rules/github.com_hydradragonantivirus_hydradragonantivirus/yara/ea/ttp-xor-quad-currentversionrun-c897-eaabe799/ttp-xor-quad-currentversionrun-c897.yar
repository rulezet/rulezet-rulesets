rule TTP_XOR_QUAD_CurrentVersionRun_c897 {
  strings:
    $key_c897 = { 9b f8 [2] bf f6 [2] 94 da [2] ba f8 [2] ae e3 [2] a1 f9 [2] bf e4 [2] bd e5 [2] a6 e3 [2] ba e4 [2] a6 cb }

  condition:
    any of them
}