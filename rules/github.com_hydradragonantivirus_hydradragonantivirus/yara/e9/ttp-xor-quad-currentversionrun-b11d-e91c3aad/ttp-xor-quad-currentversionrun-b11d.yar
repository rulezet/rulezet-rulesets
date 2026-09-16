rule TTP_XOR_QUAD_CurrentVersionRun_b11d {
  strings:
    $key_b11d = { e2 72 [2] c6 7c [2] ed 50 [2] c3 72 [2] d7 69 [2] d8 73 [2] c6 6e [2] c4 6f [2] df 69 [2] c3 6e [2] df 41 }

  condition:
    any of them
}