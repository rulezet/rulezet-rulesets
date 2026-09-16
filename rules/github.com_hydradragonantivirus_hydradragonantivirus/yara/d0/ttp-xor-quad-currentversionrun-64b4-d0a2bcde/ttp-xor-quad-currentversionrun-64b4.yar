rule TTP_XOR_QUAD_CurrentVersionRun_64b4 {
  strings:
    $key_64b4 = { 37 db [2] 13 d5 [2] 38 f9 [2] 16 db [2] 02 c0 [2] 0d da [2] 13 c7 [2] 11 c6 [2] 0a c0 [2] 16 c7 [2] 0a e8 }

  condition:
    any of them
}