rule TTP_XOR_QUAD_CurrentVersionRun_f430 {
  strings:
    $key_f430 = { a7 5f [2] 83 51 [2] a8 7d [2] 86 5f [2] 92 44 [2] 9d 5e [2] 83 43 [2] 81 42 [2] 9a 44 [2] 86 43 [2] 9a 6c }

  condition:
    any of them
}