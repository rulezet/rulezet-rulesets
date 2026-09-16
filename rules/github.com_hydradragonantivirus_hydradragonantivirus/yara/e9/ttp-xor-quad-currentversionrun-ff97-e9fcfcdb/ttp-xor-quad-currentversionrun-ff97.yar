rule TTP_XOR_QUAD_CurrentVersionRun_ff97 {
  strings:
    $key_ff97 = { ac f8 [2] 88 f6 [2] a3 da [2] 8d f8 [2] 99 e3 [2] 96 f9 [2] 88 e4 [2] 8a e5 [2] 91 e3 [2] 8d e4 [2] 91 cb }

  condition:
    any of them
}