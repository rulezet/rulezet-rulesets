rule TTP_XOR_QUAD_CurrentVersionRun_a016 {
  strings:
    $key_a016 = { f3 79 [2] d7 77 [2] fc 5b [2] d2 79 [2] c6 62 [2] c9 78 [2] d7 65 [2] d5 64 [2] ce 62 [2] d2 65 [2] ce 4a }

  condition:
    any of them
}