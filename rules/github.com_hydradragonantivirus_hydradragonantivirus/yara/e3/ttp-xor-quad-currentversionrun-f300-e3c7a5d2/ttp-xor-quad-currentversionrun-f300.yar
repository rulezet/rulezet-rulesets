rule TTP_XOR_QUAD_CurrentVersionRun_f300 {
  strings:
    $key_f300 = { a0 6f [2] 84 61 [2] af 4d [2] 81 6f [2] 95 74 [2] 9a 6e [2] 84 73 [2] 86 72 [2] 9d 74 [2] 81 73 [2] 9d 5c }

  condition:
    any of them
}