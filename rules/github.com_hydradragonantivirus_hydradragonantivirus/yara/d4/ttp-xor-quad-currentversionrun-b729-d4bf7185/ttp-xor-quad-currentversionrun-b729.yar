rule TTP_XOR_QUAD_CurrentVersionRun_b729 {
  strings:
    $key_b729 = { e4 46 [2] c0 48 [2] eb 64 [2] c5 46 [2] d1 5d [2] de 47 [2] c0 5a [2] c2 5b [2] d9 5d [2] c5 5a [2] d9 75 }

  condition:
    any of them
}