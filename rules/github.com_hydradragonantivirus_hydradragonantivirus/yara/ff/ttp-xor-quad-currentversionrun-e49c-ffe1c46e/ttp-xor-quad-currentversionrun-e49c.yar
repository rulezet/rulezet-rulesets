rule TTP_XOR_QUAD_CurrentVersionRun_e49c {
  strings:
    $key_e49c = { b7 f3 [2] 93 fd [2] b8 d1 [2] 96 f3 [2] 82 e8 [2] 8d f2 [2] 93 ef [2] 91 ee [2] 8a e8 [2] 96 ef [2] 8a c0 }

  condition:
    any of them
}