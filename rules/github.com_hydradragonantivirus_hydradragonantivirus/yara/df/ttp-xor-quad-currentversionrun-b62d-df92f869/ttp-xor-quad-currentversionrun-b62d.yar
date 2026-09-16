rule TTP_XOR_QUAD_CurrentVersionRun_b62d {
  strings:
    $key_b62d = { e5 42 [2] c1 4c [2] ea 60 [2] c4 42 [2] d0 59 [2] df 43 [2] c1 5e [2] c3 5f [2] d8 59 [2] c4 5e [2] d8 71 }

  condition:
    any of them
}