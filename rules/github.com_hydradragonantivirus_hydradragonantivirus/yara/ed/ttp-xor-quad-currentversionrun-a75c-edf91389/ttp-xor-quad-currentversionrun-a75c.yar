rule TTP_XOR_QUAD_CurrentVersionRun_a75c {
  strings:
    $key_a75c = { f4 33 [2] d0 3d [2] fb 11 [2] d5 33 [2] c1 28 [2] ce 32 [2] d0 2f [2] d2 2e [2] c9 28 [2] d5 2f [2] c9 00 }

  condition:
    any of them
}