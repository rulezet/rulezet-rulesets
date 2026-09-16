rule TTP_XOR_QUAD_CurrentVersionRun_b0d6 {
  strings:
    $key_b0d6 = { e3 b9 [2] c7 b7 [2] ec 9b [2] c2 b9 [2] d6 a2 [2] d9 b8 [2] c7 a5 [2] c5 a4 [2] de a2 [2] c2 a5 [2] de 8a }

  condition:
    any of them
}