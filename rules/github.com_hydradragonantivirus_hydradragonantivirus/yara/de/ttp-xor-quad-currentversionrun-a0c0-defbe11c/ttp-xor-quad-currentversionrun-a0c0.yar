rule TTP_XOR_QUAD_CurrentVersionRun_a0c0 {
  strings:
    $key_a0c0 = { f3 af [2] d7 a1 [2] fc 8d [2] d2 af [2] c6 b4 [2] c9 ae [2] d7 b3 [2] d5 b2 [2] ce b4 [2] d2 b3 [2] ce 9c }

  condition:
    any of them
}