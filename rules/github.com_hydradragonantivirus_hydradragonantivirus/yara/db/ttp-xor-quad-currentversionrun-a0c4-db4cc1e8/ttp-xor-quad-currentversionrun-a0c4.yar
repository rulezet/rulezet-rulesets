rule TTP_XOR_QUAD_CurrentVersionRun_a0c4 {
  strings:
    $key_a0c4 = { f3 ab [2] d7 a5 [2] fc 89 [2] d2 ab [2] c6 b0 [2] c9 aa [2] d7 b7 [2] d5 b6 [2] ce b0 [2] d2 b7 [2] ce 98 }

  condition:
    any of them
}