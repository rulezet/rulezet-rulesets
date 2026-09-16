rule TTP_XOR_QUAD_CurrentVersionRun_b40e {
  strings:
    $key_b40e = { e7 61 [2] c3 6f [2] e8 43 [2] c6 61 [2] d2 7a [2] dd 60 [2] c3 7d [2] c1 7c [2] da 7a [2] c6 7d [2] da 52 }

  condition:
    any of them
}