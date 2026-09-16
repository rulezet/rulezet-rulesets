rule TTP_XOR_QUAD_CurrentVersionRun_b133 {
  strings:
    $key_b133 = { e2 5c [2] c6 52 [2] ed 7e [2] c3 5c [2] d7 47 [2] d8 5d [2] c6 40 [2] c4 41 [2] df 47 [2] c3 40 [2] df 6f }

  condition:
    any of them
}