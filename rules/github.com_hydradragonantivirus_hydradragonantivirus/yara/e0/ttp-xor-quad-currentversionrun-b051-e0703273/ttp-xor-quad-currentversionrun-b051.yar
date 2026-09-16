rule TTP_XOR_QUAD_CurrentVersionRun_b051 {
  strings:
    $key_b051 = { e3 3e [2] c7 30 [2] ec 1c [2] c2 3e [2] d6 25 [2] d9 3f [2] c7 22 [2] c5 23 [2] de 25 [2] c2 22 [2] de 0d }

  condition:
    any of them
}