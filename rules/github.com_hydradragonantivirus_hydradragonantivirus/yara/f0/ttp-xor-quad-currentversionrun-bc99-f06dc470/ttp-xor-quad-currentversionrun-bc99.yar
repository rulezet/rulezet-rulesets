rule TTP_XOR_QUAD_CurrentVersionRun_bc99 {
  strings:
    $key_bc99 = { ef f6 [2] cb f8 [2] e0 d4 [2] ce f6 [2] da ed [2] d5 f7 [2] cb ea [2] c9 eb [2] d2 ed [2] ce ea [2] d2 c5 }

  condition:
    any of them
}