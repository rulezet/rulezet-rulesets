rule TTP_XOR_QUAD_CurrentVersionRun_b887 {
  strings:
    $key_b887 = { eb e8 [2] cf e6 [2] e4 ca [2] ca e8 [2] de f3 [2] d1 e9 [2] cf f4 [2] cd f5 [2] d6 f3 [2] ca f4 [2] d6 db }

  condition:
    any of them
}