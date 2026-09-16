rule TTP_XOR_QUAD_CurrentVersionRun_b0d2 {
  strings:
    $key_b0d2 = { e3 bd [2] c7 b3 [2] ec 9f [2] c2 bd [2] d6 a6 [2] d9 bc [2] c7 a1 [2] c5 a0 [2] de a6 [2] c2 a1 [2] de 8e }

  condition:
    any of them
}