rule TTP_XOR_QUAD_CurrentVersionRun_e2db {
  strings:
    $key_e2db = { b1 b4 [2] 95 ba [2] be 96 [2] 90 b4 [2] 84 af [2] 8b b5 [2] 95 a8 [2] 97 a9 [2] 8c af [2] 90 a8 [2] 8c 87 }

  condition:
    any of them
}