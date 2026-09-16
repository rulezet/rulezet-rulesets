rule TTP_XOR_QUAD_CurrentVersionRun_a4da {
  strings:
    $key_a4da = { f7 b5 [2] d3 bb [2] f8 97 [2] d6 b5 [2] c2 ae [2] cd b4 [2] d3 a9 [2] d1 a8 [2] ca ae [2] d6 a9 [2] ca 86 }

  condition:
    any of them
}