rule TTP_XOR_QUAD_CurrentVersionRun_fbef {
  strings:
    $key_fbef = { a8 80 [2] 8c 8e [2] a7 a2 [2] 89 80 [2] 9d 9b [2] 92 81 [2] 8c 9c [2] 8e 9d [2] 95 9b [2] 89 9c [2] 95 b3 }

  condition:
    any of them
}