rule TTP_XOR_QUAD_CurrentVersionRun_a0ed {
  strings:
    $key_a0ed = { f3 82 [2] d7 8c [2] fc a0 [2] d2 82 [2] c6 99 [2] c9 83 [2] d7 9e [2] d5 9f [2] ce 99 [2] d2 9e [2] ce b1 }

  condition:
    any of them
}