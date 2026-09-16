rule TTP_XOR_QUAD_CurrentVersionRun_faa8 {
  strings:
    $key_faa8 = { a9 c7 [2] 8d c9 [2] a6 e5 [2] 88 c7 [2] 9c dc [2] 93 c6 [2] 8d db [2] 8f da [2] 94 dc [2] 88 db [2] 94 f4 }

  condition:
    any of them
}