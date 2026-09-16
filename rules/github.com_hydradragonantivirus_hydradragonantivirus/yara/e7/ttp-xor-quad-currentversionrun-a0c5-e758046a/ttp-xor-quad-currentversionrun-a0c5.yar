rule TTP_XOR_QUAD_CurrentVersionRun_a0c5 {
  strings:
    $key_a0c5 = { f3 aa [2] d7 a4 [2] fc 88 [2] d2 aa [2] c6 b1 [2] c9 ab [2] d7 b6 [2] d5 b7 [2] ce b1 [2] d2 b6 [2] ce 99 }

  condition:
    any of them
}