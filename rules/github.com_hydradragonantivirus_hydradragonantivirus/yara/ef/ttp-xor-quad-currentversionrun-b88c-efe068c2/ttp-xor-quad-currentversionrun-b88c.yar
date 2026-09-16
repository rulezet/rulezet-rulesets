rule TTP_XOR_QUAD_CurrentVersionRun_b88c {
  strings:
    $key_b88c = { eb e3 [2] cf ed [2] e4 c1 [2] ca e3 [2] de f8 [2] d1 e2 [2] cf ff [2] cd fe [2] d6 f8 [2] ca ff [2] d6 d0 }

  condition:
    any of them
}