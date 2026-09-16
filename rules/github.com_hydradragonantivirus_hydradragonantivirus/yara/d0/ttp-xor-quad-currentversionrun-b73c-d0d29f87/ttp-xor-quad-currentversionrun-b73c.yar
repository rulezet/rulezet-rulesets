rule TTP_XOR_QUAD_CurrentVersionRun_b73c {
  strings:
    $key_b73c = { e4 53 [2] c0 5d [2] eb 71 [2] c5 53 [2] d1 48 [2] de 52 [2] c0 4f [2] c2 4e [2] d9 48 [2] c5 4f [2] d9 60 }

  condition:
    any of them
}