rule TTP_XOR_QUAD_CurrentVersionRun_2896 {
  strings:
    $key_2896 = { 7b f9 [2] 5f f7 [2] 74 db [2] 5a f9 [2] 4e e2 [2] 41 f8 [2] 5f e5 [2] 5d e4 [2] 46 e2 [2] 5a e5 [2] 46 ca }

  condition:
    any of them
}