rule TTP_XOR_QUAD_CurrentVersionRun_f41d {
  strings:
    $key_f41d = { a7 72 [2] 83 7c [2] a8 50 [2] 86 72 [2] 92 69 [2] 9d 73 [2] 83 6e [2] 81 6f [2] 9a 69 [2] 86 6e [2] 9a 41 }

  condition:
    any of them
}