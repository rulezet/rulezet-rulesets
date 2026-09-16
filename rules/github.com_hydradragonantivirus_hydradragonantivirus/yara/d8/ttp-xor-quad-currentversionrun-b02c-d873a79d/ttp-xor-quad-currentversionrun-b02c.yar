rule TTP_XOR_QUAD_CurrentVersionRun_b02c {
  strings:
    $key_b02c = { e3 43 [2] c7 4d [2] ec 61 [2] c2 43 [2] d6 58 [2] d9 42 [2] c7 5f [2] c5 5e [2] de 58 [2] c2 5f [2] de 70 }

  condition:
    any of them
}