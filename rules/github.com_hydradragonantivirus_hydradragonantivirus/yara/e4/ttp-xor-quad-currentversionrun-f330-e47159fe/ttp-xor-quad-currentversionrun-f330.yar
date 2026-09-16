rule TTP_XOR_QUAD_CurrentVersionRun_f330 {
  strings:
    $key_f330 = { a0 5f [2] 84 51 [2] af 7d [2] 81 5f [2] 95 44 [2] 9a 5e [2] 84 43 [2] 86 42 [2] 9d 44 [2] 81 43 [2] 9d 6c }

  condition:
    any of them
}