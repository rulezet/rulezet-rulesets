rule TTP_XOR_QUAD_CurrentVersionRun_4c96 {
  strings:
    $key_4c96 = { 1f f9 [2] 3b f7 [2] 10 db [2] 3e f9 [2] 2a e2 [2] 25 f8 [2] 3b e5 [2] 39 e4 [2] 22 e2 [2] 3e e5 [2] 22 ca }

  condition:
    any of them
}