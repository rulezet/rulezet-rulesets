rule TTP_XOR_QUAD_CurrentVersionRun_f481 {
  strings:
    $key_f481 = { a7 ee [2] 83 e0 [2] a8 cc [2] 86 ee [2] 92 f5 [2] 9d ef [2] 83 f2 [2] 81 f3 [2] 9a f5 [2] 86 f2 [2] 9a dd }

  condition:
    any of them
}