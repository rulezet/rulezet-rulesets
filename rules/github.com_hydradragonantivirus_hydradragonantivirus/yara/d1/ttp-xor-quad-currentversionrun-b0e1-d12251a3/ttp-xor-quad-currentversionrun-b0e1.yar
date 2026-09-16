rule TTP_XOR_QUAD_CurrentVersionRun_b0e1 {
  strings:
    $key_b0e1 = { e3 8e [2] c7 80 [2] ec ac [2] c2 8e [2] d6 95 [2] d9 8f [2] c7 92 [2] c5 93 [2] de 95 [2] c2 92 [2] de bd }

  condition:
    any of them
}