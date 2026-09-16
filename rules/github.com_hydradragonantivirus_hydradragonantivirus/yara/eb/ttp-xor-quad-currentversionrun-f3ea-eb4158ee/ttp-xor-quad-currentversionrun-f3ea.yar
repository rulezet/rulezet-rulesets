rule TTP_XOR_QUAD_CurrentVersionRun_f3ea {
  strings:
    $key_f3ea = { a0 85 [2] 84 8b [2] af a7 [2] 81 85 [2] 95 9e [2] 9a 84 [2] 84 99 [2] 86 98 [2] 9d 9e [2] 81 99 [2] 9d b6 }

  condition:
    any of them
}