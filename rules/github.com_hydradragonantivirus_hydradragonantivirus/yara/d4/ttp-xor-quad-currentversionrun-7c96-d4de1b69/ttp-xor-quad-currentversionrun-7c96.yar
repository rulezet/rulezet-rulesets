rule TTP_XOR_QUAD_CurrentVersionRun_7c96 {
  strings:
    $key_7c96 = { 2f f9 [2] 0b f7 [2] 20 db [2] 0e f9 [2] 1a e2 [2] 15 f8 [2] 0b e5 [2] 09 e4 [2] 12 e2 [2] 0e e5 [2] 12 ca }

  condition:
    any of them
}