rule TTP_XOR_QUAD_CurrentVersionRun_f1b4 {
  strings:
    $key_f1b4 = { a2 db [2] 86 d5 [2] ad f9 [2] 83 db [2] 97 c0 [2] 98 da [2] 86 c7 [2] 84 c6 [2] 9f c0 [2] 83 c7 [2] 9f e8 }

  condition:
    any of them
}