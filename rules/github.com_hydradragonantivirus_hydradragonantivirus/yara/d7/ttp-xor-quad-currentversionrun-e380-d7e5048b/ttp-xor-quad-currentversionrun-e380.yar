rule TTP_XOR_QUAD_CurrentVersionRun_e380 {
  strings:
    $key_e380 = { b0 ef [2] 94 e1 [2] bf cd [2] 91 ef [2] 85 f4 [2] 8a ee [2] 94 f3 [2] 96 f2 [2] 8d f4 [2] 91 f3 [2] 8d dc }

  condition:
    any of them
}