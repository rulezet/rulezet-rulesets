rule TTP_XOR_QUAD_CurrentVersionRun_b1e1 {
  strings:
    $key_b1e1 = { e2 8e [2] c6 80 [2] ed ac [2] c3 8e [2] d7 95 [2] d8 8f [2] c6 92 [2] c4 93 [2] df 95 [2] c3 92 [2] df bd }

  condition:
    any of them
}