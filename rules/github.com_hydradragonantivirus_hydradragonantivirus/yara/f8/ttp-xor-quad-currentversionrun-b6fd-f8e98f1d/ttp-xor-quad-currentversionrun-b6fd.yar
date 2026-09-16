rule TTP_XOR_QUAD_CurrentVersionRun_b6fd {
  strings:
    $key_b6fd = { e5 92 [2] c1 9c [2] ea b0 [2] c4 92 [2] d0 89 [2] df 93 [2] c1 8e [2] c3 8f [2] d8 89 [2] c4 8e [2] d8 a1 }

  condition:
    any of them
}