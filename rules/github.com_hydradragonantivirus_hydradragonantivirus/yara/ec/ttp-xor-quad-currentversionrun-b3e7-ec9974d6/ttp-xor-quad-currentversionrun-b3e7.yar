rule TTP_XOR_QUAD_CurrentVersionRun_b3e7 {
  strings:
    $key_b3e7 = { e0 88 [2] c4 86 [2] ef aa [2] c1 88 [2] d5 93 [2] da 89 [2] c4 94 [2] c6 95 [2] dd 93 [2] c1 94 [2] dd bb }

  condition:
    any of them
}