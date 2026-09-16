rule TTP_XOR_QUAD_CurrentVersionRun_b3dc {
  strings:
    $key_b3dc = { e0 b3 [2] c4 bd [2] ef 91 [2] c1 b3 [2] d5 a8 [2] da b2 [2] c4 af [2] c6 ae [2] dd a8 [2] c1 af [2] dd 80 }

  condition:
    any of them
}