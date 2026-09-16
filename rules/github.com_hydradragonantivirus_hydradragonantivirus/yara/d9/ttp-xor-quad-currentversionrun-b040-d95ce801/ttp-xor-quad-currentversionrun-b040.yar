rule TTP_XOR_QUAD_CurrentVersionRun_b040 {
  strings:
    $key_b040 = { e3 2f [2] c7 21 [2] ec 0d [2] c2 2f [2] d6 34 [2] d9 2e [2] c7 33 [2] c5 32 [2] de 34 [2] c2 33 [2] de 1c }

  condition:
    any of them
}