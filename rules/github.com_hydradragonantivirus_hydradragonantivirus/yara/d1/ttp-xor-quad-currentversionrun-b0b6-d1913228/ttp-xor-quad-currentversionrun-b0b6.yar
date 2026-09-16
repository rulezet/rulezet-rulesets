rule TTP_XOR_QUAD_CurrentVersionRun_b0b6 {
  strings:
    $key_b0b6 = { e3 d9 [2] c7 d7 [2] ec fb [2] c2 d9 [2] d6 c2 [2] d9 d8 [2] c7 c5 [2] c5 c4 [2] de c2 [2] c2 c5 [2] de ea }

  condition:
    any of them
}