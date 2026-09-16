rule TTP_XOR_QUAD_CurrentVersionRun_e4da {
  strings:
    $key_e4da = { b7 b5 [2] 93 bb [2] b8 97 [2] 96 b5 [2] 82 ae [2] 8d b4 [2] 93 a9 [2] 91 a8 [2] 8a ae [2] 96 a9 [2] 8a 86 }

  condition:
    any of them
}