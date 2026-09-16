rule TTP_XOR_QUAD_CurrentVersionRun_f250 {
  strings:
    $key_f250 = { a1 3f [2] 85 31 [2] ae 1d [2] 80 3f [2] 94 24 [2] 9b 3e [2] 85 23 [2] 87 22 [2] 9c 24 [2] 80 23 [2] 9c 0c }

  condition:
    any of them
}