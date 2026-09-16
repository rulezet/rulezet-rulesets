rule TTP_XOR_QUAD_CurrentVersionRun_b731 {
  strings:
    $key_b731 = { e4 5e [2] c0 50 [2] eb 7c [2] c5 5e [2] d1 45 [2] de 5f [2] c0 42 [2] c2 43 [2] d9 45 [2] c5 42 [2] d9 6d }

  condition:
    any of them
}