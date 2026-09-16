rule TTP_XOR_QUAD_CurrentVersionRun_7496 {
  strings:
    $key_7496 = { 27 f9 [2] 03 f7 [2] 28 db [2] 06 f9 [2] 12 e2 [2] 1d f8 [2] 03 e5 [2] 01 e4 [2] 1a e2 [2] 06 e5 [2] 1a ca }

  condition:
    any of them
}