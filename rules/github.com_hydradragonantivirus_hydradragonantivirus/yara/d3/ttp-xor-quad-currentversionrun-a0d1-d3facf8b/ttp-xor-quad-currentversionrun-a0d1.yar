rule TTP_XOR_QUAD_CurrentVersionRun_a0d1 {
  strings:
    $key_a0d1 = { f3 be [2] d7 b0 [2] fc 9c [2] d2 be [2] c6 a5 [2] c9 bf [2] d7 a2 [2] d5 a3 [2] ce a5 [2] d2 a2 [2] ce 8d }

  condition:
    any of them
}