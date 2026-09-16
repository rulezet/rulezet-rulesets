rule TTP_XOR_QUAD_CurrentVersionRun_b70e {
  strings:
    $key_b70e = { e4 61 [2] c0 6f [2] eb 43 [2] c5 61 [2] d1 7a [2] de 60 [2] c0 7d [2] c2 7c [2] d9 7a [2] c5 7d [2] d9 52 }

  condition:
    any of them
}