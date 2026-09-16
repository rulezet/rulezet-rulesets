rule TTP_XOR_QUAD_CurrentVersionRun_a04c {
  strings:
    $key_a04c = { f3 23 [2] d7 2d [2] fc 01 [2] d2 23 [2] c6 38 [2] c9 22 [2] d7 3f [2] d5 3e [2] ce 38 [2] d2 3f [2] ce 10 }

  condition:
    any of them
}