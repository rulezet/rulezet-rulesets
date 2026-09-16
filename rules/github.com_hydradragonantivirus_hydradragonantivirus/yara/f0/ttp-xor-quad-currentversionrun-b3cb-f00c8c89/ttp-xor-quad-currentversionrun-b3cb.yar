rule TTP_XOR_QUAD_CurrentVersionRun_b3cb {
  strings:
    $key_b3cb = { e0 a4 [2] c4 aa [2] ef 86 [2] c1 a4 [2] d5 bf [2] da a5 [2] c4 b8 [2] c6 b9 [2] dd bf [2] c1 b8 [2] dd 97 }

  condition:
    any of them
}