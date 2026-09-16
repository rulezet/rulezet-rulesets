rule TTP_XOR_QUAD_CurrentVersionRun_3c96 {
  strings:
    $key_3c96 = { 6f f9 [2] 4b f7 [2] 60 db [2] 4e f9 [2] 5a e2 [2] 55 f8 [2] 4b e5 [2] 49 e4 [2] 52 e2 [2] 4e e5 [2] 52 ca }

  condition:
    any of them
}