rule TTP_XOR_QUAD_CurrentVersionRun_a63a {
  strings:
    $key_a63a = { f5 55 [2] d1 5b [2] fa 77 [2] d4 55 [2] c0 4e [2] cf 54 [2] d1 49 [2] d3 48 [2] c8 4e [2] d4 49 [2] c8 66 }

  condition:
    any of them
}