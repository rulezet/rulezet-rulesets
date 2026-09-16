rule TTP_XOR_QUAD_CurrentVersionRun_a0d9 {
  strings:
    $key_a0d9 = { f3 b6 [2] d7 b8 [2] fc 94 [2] d2 b6 [2] c6 ad [2] c9 b7 [2] d7 aa [2] d5 ab [2] ce ad [2] d2 aa [2] ce 85 }

  condition:
    any of them
}