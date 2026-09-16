rule TTP_XOR_QUAD_CurrentVersionRun_a04d {
  strings:
    $key_a04d = { f3 22 [2] d7 2c [2] fc 00 [2] d2 22 [2] c6 39 [2] c9 23 [2] d7 3e [2] d5 3f [2] ce 39 [2] d2 3e [2] ce 11 }

  condition:
    any of them
}