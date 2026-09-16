rule TTP_XOR_QUAD_CurrentVersionRun_5596 {
  strings:
    $key_5596 = { 06 f9 [2] 22 f7 [2] 09 db [2] 27 f9 [2] 33 e2 [2] 3c f8 [2] 22 e5 [2] 20 e4 [2] 3b e2 [2] 27 e5 [2] 3b ca }

  condition:
    any of them
}