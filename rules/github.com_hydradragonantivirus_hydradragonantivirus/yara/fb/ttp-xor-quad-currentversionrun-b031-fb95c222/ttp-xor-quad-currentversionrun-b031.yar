rule TTP_XOR_QUAD_CurrentVersionRun_b031 {
  strings:
    $key_b031 = { e3 5e [2] c7 50 [2] ec 7c [2] c2 5e [2] d6 45 [2] d9 5f [2] c7 42 [2] c5 43 [2] de 45 [2] c2 42 [2] de 6d }

  condition:
    any of them
}