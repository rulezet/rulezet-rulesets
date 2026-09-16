rule TTP_XOR_QUAD_CurrentVersionRun_a076 {
  strings:
    $key_a076 = { f3 19 [2] d7 17 [2] fc 3b [2] d2 19 [2] c6 02 [2] c9 18 [2] d7 05 [2] d5 04 [2] ce 02 [2] d2 05 [2] ce 2a }

  condition:
    any of them
}