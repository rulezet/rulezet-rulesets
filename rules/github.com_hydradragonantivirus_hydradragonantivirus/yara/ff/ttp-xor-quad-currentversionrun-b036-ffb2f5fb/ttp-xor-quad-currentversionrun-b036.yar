rule TTP_XOR_QUAD_CurrentVersionRun_b036 {
  strings:
    $key_b036 = { e3 59 [2] c7 57 [2] ec 7b [2] c2 59 [2] d6 42 [2] d9 58 [2] c7 45 [2] c5 44 [2] de 42 [2] c2 45 [2] de 6a }

  condition:
    any of them
}