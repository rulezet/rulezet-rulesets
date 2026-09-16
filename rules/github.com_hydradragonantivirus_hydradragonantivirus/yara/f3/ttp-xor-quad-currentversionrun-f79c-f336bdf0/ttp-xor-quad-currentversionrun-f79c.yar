rule TTP_XOR_QUAD_CurrentVersionRun_f79c {
  strings:
    $key_f79c = { a4 f3 [2] 80 fd [2] ab d1 [2] 85 f3 [2] 91 e8 [2] 9e f2 [2] 80 ef [2] 82 ee [2] 99 e8 [2] 85 ef [2] 99 c0 }

  condition:
    any of them
}