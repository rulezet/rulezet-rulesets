rule TTP_XOR_QUAD_CurrentVersionRun_b14e {
  strings:
    $key_b14e = { e2 21 [2] c6 2f [2] ed 03 [2] c3 21 [2] d7 3a [2] d8 20 [2] c6 3d [2] c4 3c [2] df 3a [2] c3 3d [2] df 12 }

  condition:
    any of them
}