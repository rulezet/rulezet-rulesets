rule TTP_XOR_QUAD_CurrentVersionRun_b714 {
  strings:
    $key_b714 = { e4 7b [2] c0 75 [2] eb 59 [2] c5 7b [2] d1 60 [2] de 7a [2] c0 67 [2] c2 66 [2] d9 60 [2] c5 67 [2] d9 48 }

  condition:
    any of them
}