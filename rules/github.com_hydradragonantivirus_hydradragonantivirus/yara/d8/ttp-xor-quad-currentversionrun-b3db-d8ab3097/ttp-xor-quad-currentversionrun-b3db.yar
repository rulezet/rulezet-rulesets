rule TTP_XOR_QUAD_CurrentVersionRun_b3db {
  strings:
    $key_b3db = { e0 b4 [2] c4 ba [2] ef 96 [2] c1 b4 [2] d5 af [2] da b5 [2] c4 a8 [2] c6 a9 [2] dd af [2] c1 a8 [2] dd 87 }

  condition:
    any of them
}