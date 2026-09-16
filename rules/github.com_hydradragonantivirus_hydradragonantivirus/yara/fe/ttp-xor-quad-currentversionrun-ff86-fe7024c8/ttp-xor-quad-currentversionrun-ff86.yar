rule TTP_XOR_QUAD_CurrentVersionRun_ff86 {
  strings:
    $key_ff86 = { ac e9 [2] 88 e7 [2] a3 cb [2] 8d e9 [2] 99 f2 [2] 96 e8 [2] 88 f5 [2] 8a f4 [2] 91 f2 [2] 8d f5 [2] 91 da }

  condition:
    any of them
}