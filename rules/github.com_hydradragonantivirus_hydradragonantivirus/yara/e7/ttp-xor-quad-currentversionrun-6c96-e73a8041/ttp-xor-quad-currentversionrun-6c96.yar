rule TTP_XOR_QUAD_CurrentVersionRun_6c96 {
  strings:
    $key_6c96 = { 3f f9 [2] 1b f7 [2] 30 db [2] 1e f9 [2] 0a e2 [2] 05 f8 [2] 1b e5 [2] 19 e4 [2] 02 e2 [2] 1e e5 [2] 02 ca }

  condition:
    any of them
}