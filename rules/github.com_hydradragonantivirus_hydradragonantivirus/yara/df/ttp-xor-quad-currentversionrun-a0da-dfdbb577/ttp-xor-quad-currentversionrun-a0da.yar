rule TTP_XOR_QUAD_CurrentVersionRun_a0da {
  strings:
    $key_a0da = { f3 b5 [2] d7 bb [2] fc 97 [2] d2 b5 [2] c6 ae [2] c9 b4 [2] d7 a9 [2] d5 a8 [2] ce ae [2] d2 a9 [2] ce 86 }

  condition:
    any of them
}