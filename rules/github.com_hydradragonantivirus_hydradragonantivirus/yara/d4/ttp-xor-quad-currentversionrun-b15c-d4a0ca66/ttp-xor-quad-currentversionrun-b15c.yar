rule TTP_XOR_QUAD_CurrentVersionRun_b15c {
  strings:
    $key_b15c = { e2 33 [2] c6 3d [2] ed 11 [2] c3 33 [2] d7 28 [2] d8 32 [2] c6 2f [2] c4 2e [2] df 28 [2] c3 2f [2] df 00 }

  condition:
    any of them
}