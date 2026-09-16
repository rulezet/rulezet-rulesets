rule TTP_XOR_QUAD_CurrentVersionRun_b65d {
  strings:
    $key_b65d = { e5 32 [2] c1 3c [2] ea 10 [2] c4 32 [2] d0 29 [2] df 33 [2] c1 2e [2] c3 2f [2] d8 29 [2] c4 2e [2] d8 01 }

  condition:
    any of them
}