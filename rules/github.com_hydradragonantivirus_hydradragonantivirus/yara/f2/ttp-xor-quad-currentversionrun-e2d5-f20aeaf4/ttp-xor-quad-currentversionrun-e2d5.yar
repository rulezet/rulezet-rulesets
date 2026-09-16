rule TTP_XOR_QUAD_CurrentVersionRun_e2d5 {
  strings:
    $key_e2d5 = { b1 ba [2] 95 b4 [2] be 98 [2] 90 ba [2] 84 a1 [2] 8b bb [2] 95 a6 [2] 97 a7 [2] 8c a1 [2] 90 a6 [2] 8c 89 }

  condition:
    any of them
}