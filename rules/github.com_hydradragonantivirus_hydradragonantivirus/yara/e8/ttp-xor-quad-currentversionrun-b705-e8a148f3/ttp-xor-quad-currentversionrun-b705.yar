rule TTP_XOR_QUAD_CurrentVersionRun_b705 {
  strings:
    $key_b705 = { e4 6a [2] c0 64 [2] eb 48 [2] c5 6a [2] d1 71 [2] de 6b [2] c0 76 [2] c2 77 [2] d9 71 [2] c5 76 [2] d9 59 }

  condition:
    any of them
}