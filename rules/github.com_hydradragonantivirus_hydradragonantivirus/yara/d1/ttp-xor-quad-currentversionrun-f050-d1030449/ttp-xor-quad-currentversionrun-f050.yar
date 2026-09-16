rule TTP_XOR_QUAD_CurrentVersionRun_f050 {
  strings:
    $key_f050 = { a3 3f [2] 87 31 [2] ac 1d [2] 82 3f [2] 96 24 [2] 99 3e [2] 87 23 [2] 85 22 [2] 9e 24 [2] 82 23 [2] 9e 0c }

  condition:
    any of them
}