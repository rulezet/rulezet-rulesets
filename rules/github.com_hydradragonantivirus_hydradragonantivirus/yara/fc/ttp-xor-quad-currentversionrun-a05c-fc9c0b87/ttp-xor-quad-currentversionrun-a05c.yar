rule TTP_XOR_QUAD_CurrentVersionRun_a05c {
  strings:
    $key_a05c = { f3 33 [2] d7 3d [2] fc 11 [2] d2 33 [2] c6 28 [2] c9 32 [2] d7 2f [2] d5 2e [2] ce 28 [2] d2 2f [2] ce 00 }

  condition:
    any of them
}