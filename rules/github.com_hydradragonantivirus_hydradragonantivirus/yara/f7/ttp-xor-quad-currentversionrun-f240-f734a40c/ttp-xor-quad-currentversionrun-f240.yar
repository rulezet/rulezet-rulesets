rule TTP_XOR_QUAD_CurrentVersionRun_f240 {
  strings:
    $key_f240 = { a1 2f [2] 85 21 [2] ae 0d [2] 80 2f [2] 94 34 [2] 9b 2e [2] 85 33 [2] 87 32 [2] 9c 34 [2] 80 33 [2] 9c 1c }

  condition:
    any of them
}