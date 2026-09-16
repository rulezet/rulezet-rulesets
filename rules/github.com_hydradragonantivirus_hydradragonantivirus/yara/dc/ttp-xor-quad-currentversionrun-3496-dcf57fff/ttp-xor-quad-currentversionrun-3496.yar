rule TTP_XOR_QUAD_CurrentVersionRun_3496 {
  strings:
    $key_3496 = { 67 f9 [2] 43 f7 [2] 68 db [2] 46 f9 [2] 52 e2 [2] 5d f8 [2] 43 e5 [2] 41 e4 [2] 5a e2 [2] 46 e5 [2] 5a ca }

  condition:
    any of them
}