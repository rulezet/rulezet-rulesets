rule TTP_XOR_QUAD_CurrentVersionRun_b73e {
  strings:
    $key_b73e = { e4 51 [2] c0 5f [2] eb 73 [2] c5 51 [2] d1 4a [2] de 50 [2] c0 4d [2] c2 4c [2] d9 4a [2] c5 4d [2] d9 62 }

  condition:
    any of them
}