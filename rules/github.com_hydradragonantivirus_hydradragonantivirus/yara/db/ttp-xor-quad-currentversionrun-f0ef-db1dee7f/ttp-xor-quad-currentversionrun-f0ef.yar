rule TTP_XOR_QUAD_CurrentVersionRun_f0ef {
  strings:
    $key_f0ef = { a3 80 [2] 87 8e [2] ac a2 [2] 82 80 [2] 96 9b [2] 99 81 [2] 87 9c [2] 85 9d [2] 9e 9b [2] 82 9c [2] 9e b3 }

  condition:
    any of them
}