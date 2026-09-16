rule TTP_XOR_QUAD_CurrentVersionRun_b16d {
  strings:
    $key_b16d = { e2 02 [2] c6 0c [2] ed 20 [2] c3 02 [2] d7 19 [2] d8 03 [2] c6 1e [2] c4 1f [2] df 19 [2] c3 1e [2] df 31 }

  condition:
    any of them
}