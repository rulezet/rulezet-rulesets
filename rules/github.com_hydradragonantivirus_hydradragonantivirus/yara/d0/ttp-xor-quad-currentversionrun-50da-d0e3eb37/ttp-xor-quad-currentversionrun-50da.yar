rule TTP_XOR_QUAD_CurrentVersionRun_50da {
  strings:
    $key_50da = { 03 b5 [2] 27 bb [2] 0c 97 [2] 22 b5 [2] 36 ae [2] 39 b4 [2] 27 a9 [2] 25 a8 [2] 3e ae [2] 22 a9 [2] 3e 86 }

  condition:
    any of them
}