rule TTP_XOR_QUAD_CurrentVersionRun_e2b5 {
  strings:
    $key_e2b5 = { b1 da [2] 95 d4 [2] be f8 [2] 90 da [2] 84 c1 [2] 8b db [2] 95 c6 [2] 97 c7 [2] 8c c1 [2] 90 c6 [2] 8c e9 }

  condition:
    any of them
}