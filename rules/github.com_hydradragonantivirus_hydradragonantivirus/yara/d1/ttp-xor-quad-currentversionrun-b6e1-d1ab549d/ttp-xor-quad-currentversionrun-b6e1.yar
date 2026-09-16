rule TTP_XOR_QUAD_CurrentVersionRun_b6e1 {
  strings:
    $key_b6e1 = { e5 8e [2] c1 80 [2] ea ac [2] c4 8e [2] d0 95 [2] df 8f [2] c1 92 [2] c3 93 [2] d8 95 [2] c4 92 [2] d8 bd }

  condition:
    any of them
}