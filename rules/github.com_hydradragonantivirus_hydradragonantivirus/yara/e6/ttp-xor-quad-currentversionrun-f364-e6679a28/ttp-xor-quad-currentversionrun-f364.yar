rule TTP_XOR_QUAD_CurrentVersionRun_f364 {
  strings:
    $key_f364 = { a0 0b [2] 84 05 [2] af 29 [2] 81 0b [2] 95 10 [2] 9a 0a [2] 84 17 [2] 86 16 [2] 9d 10 [2] 81 17 [2] 9d 38 }

  condition:
    any of them
}