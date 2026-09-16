rule TTP_XOR_QUAD_CurrentVersionRun_b74c {
  strings:
    $key_b74c = { e4 23 [2] c0 2d [2] eb 01 [2] c5 23 [2] d1 38 [2] de 22 [2] c0 3f [2] c2 3e [2] d9 38 [2] c5 3f [2] d9 10 }

  condition:
    any of them
}