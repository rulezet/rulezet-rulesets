rule TTP_XOR_QUAD_CurrentVersionRun_3b96 {
  strings:
    $key_3b96 = { 68 f9 [2] 4c f7 [2] 67 db [2] 49 f9 [2] 5d e2 [2] 52 f8 [2] 4c e5 [2] 4e e4 [2] 55 e2 [2] 49 e5 [2] 55 ca }

  condition:
    any of them
}