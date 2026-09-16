rule TTP_XOR_QUAD_CurrentVersionRun_a052 {
  strings:
    $key_a052 = { f3 3d [2] d7 33 [2] fc 1f [2] d2 3d [2] c6 26 [2] c9 3c [2] d7 21 [2] d5 20 [2] ce 26 [2] d2 21 [2] ce 0e }

  condition:
    any of them
}