rule TTP_XOR_QUAD_CurrentVersionRun_4496 {
  strings:
    $key_4496 = { 17 f9 [2] 33 f7 [2] 18 db [2] 36 f9 [2] 22 e2 [2] 2d f8 [2] 33 e5 [2] 31 e4 [2] 2a e2 [2] 36 e5 [2] 2a ca }

  condition:
    any of them
}