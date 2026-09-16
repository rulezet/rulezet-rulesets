rule TTP_XOR_QUAD_CurrentVersionRun_0996 {
  strings:
    $key_0996 = { 5a f9 [2] 7e f7 [2] 55 db [2] 7b f9 [2] 6f e2 [2] 60 f8 [2] 7e e5 [2] 7c e4 [2] 67 e2 [2] 7b e5 [2] 67 ca }

  condition:
    any of them
}