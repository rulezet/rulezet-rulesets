rule TTP_XOR_QUAD_CurrentVersionRun_f360 {
  strings:
    $key_f360 = { a0 0f [2] 84 01 [2] af 2d [2] 81 0f [2] 95 14 [2] 9a 0e [2] 84 13 [2] 86 12 [2] 9d 14 [2] 81 13 [2] 9d 3c }

  condition:
    any of them
}