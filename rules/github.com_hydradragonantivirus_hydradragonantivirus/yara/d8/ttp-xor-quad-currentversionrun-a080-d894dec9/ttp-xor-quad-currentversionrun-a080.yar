rule TTP_XOR_QUAD_CurrentVersionRun_a080 {
  strings:
    $key_a080 = { f3 ef [2] d7 e1 [2] fc cd [2] d2 ef [2] c6 f4 [2] c9 ee [2] d7 f3 [2] d5 f2 [2] ce f4 [2] d2 f3 [2] ce dc }

  condition:
    any of them
}