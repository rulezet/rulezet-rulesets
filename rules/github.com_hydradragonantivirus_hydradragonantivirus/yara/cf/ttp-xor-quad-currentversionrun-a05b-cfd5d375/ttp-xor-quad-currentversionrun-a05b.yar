rule TTP_XOR_QUAD_CurrentVersionRun_a05b {
  strings:
    $key_a05b = { f3 34 [2] d7 3a [2] fc 16 [2] d2 34 [2] c6 2f [2] c9 35 [2] d7 28 [2] d5 29 [2] ce 2f [2] d2 28 [2] ce 07 }

  condition:
    any of them
}