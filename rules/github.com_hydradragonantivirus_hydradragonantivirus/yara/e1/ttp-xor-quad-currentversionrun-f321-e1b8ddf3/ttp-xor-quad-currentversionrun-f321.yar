rule TTP_XOR_QUAD_CurrentVersionRun_f321 {
  strings:
    $key_f321 = { a0 4e [2] 84 40 [2] af 6c [2] 81 4e [2] 95 55 [2] 9a 4f [2] 84 52 [2] 86 53 [2] 9d 55 [2] 81 52 [2] 9d 7d }

  condition:
    any of them
}