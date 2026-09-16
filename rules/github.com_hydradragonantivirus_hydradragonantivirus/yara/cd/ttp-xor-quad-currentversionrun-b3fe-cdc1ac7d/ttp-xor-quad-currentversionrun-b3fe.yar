rule TTP_XOR_QUAD_CurrentVersionRun_b3fe {
  strings:
    $key_b3fe = { e0 91 [2] c4 9f [2] ef b3 [2] c1 91 [2] d5 8a [2] da 90 [2] c4 8d [2] c6 8c [2] dd 8a [2] c1 8d [2] dd a2 }

  condition:
    any of them
}