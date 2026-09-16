rule TTP_XOR_QUAD_CurrentVersionRun_f091 {
  strings:
    $key_f091 = { a3 fe [2] 87 f0 [2] ac dc [2] 82 fe [2] 96 e5 [2] 99 ff [2] 87 e2 [2] 85 e3 [2] 9e e5 [2] 82 e2 [2] 9e cd }

  condition:
    any of them
}