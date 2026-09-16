rule TTP_XOR_QUAD_CurrentVersionRun_b15d {
  strings:
    $key_b15d = { e2 32 [2] c6 3c [2] ed 10 [2] c3 32 [2] d7 29 [2] d8 33 [2] c6 2e [2] c4 2f [2] df 29 [2] c3 2e [2] df 01 }

  condition:
    any of them
}