rule TTP_XOR_QUAD_CurrentVersionRun_4896 {
  strings:
    $key_4896 = { 1b f9 [2] 3f f7 [2] 14 db [2] 3a f9 [2] 2e e2 [2] 21 f8 [2] 3f e5 [2] 3d e4 [2] 26 e2 [2] 3a e5 [2] 26 ca }

  condition:
    any of them
}