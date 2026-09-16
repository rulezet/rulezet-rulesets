rule TTP_XOR_QUAD_CurrentVersionRun_a01a {
  strings:
    $key_a01a = { f3 75 [2] d7 7b [2] fc 57 [2] d2 75 [2] c6 6e [2] c9 74 [2] d7 69 [2] d5 68 [2] ce 6e [2] d2 69 [2] ce 46 }

  condition:
    any of them
}