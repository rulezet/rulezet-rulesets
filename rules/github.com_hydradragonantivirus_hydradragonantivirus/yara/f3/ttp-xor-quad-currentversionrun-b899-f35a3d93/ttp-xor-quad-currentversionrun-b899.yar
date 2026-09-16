rule TTP_XOR_QUAD_CurrentVersionRun_b899 {
  strings:
    $key_b899 = { eb f6 [2] cf f8 [2] e4 d4 [2] ca f6 [2] de ed [2] d1 f7 [2] cf ea [2] cd eb [2] d6 ed [2] ca ea [2] d6 c5 }

  condition:
    any of them
}