rule TTP_XOR_QUAD_CurrentVersionRun_33b5 {
  strings:
    $key_33b5 = { 60 da [2] 44 d4 [2] 6f f8 [2] 41 da [2] 55 c1 [2] 5a db [2] 44 c6 [2] 46 c7 [2] 5d c1 [2] 41 c6 [2] 5d e9 }

  condition:
    any of them
}