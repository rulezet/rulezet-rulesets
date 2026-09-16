rule TTP_XOR_QUAD_CurrentVersionRun_a061 {
  strings:
    $key_a061 = { f3 0e [2] d7 00 [2] fc 2c [2] d2 0e [2] c6 15 [2] c9 0f [2] d7 12 [2] d5 13 [2] ce 15 [2] d2 12 [2] ce 3d }

  condition:
    any of them
}