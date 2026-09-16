rule TTP_XOR_QUAD_CurrentVersionRun_a041 {
  strings:
    $key_a041 = { f3 2e [2] d7 20 [2] fc 0c [2] d2 2e [2] c6 35 [2] c9 2f [2] d7 32 [2] d5 33 [2] ce 35 [2] d2 32 [2] ce 1d }

  condition:
    any of them
}