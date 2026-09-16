rule TTP_XOR_QUAD_CurrentVersionRun_a072 {
  strings:
    $key_a072 = { f3 1d [2] d7 13 [2] fc 3f [2] d2 1d [2] c6 06 [2] c9 1c [2] d7 01 [2] d5 00 [2] ce 06 [2] d2 01 [2] ce 2e }

  condition:
    any of them
}