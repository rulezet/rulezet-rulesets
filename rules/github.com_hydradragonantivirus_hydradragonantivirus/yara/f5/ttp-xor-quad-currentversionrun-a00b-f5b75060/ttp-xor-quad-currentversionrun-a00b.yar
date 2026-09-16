rule TTP_XOR_QUAD_CurrentVersionRun_a00b {
  strings:
    $key_a00b = { f3 64 [2] d7 6a [2] fc 46 [2] d2 64 [2] c6 7f [2] c9 65 [2] d7 78 [2] d5 79 [2] ce 7f [2] d2 78 [2] ce 57 }

  condition:
    any of them
}