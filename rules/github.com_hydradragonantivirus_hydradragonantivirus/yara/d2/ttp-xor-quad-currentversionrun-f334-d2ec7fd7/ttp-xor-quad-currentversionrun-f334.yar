rule TTP_XOR_QUAD_CurrentVersionRun_f334 {
  strings:
    $key_f334 = { a0 5b [2] 84 55 [2] af 79 [2] 81 5b [2] 95 40 [2] 9a 5a [2] 84 47 [2] 86 46 [2] 9d 40 [2] 81 47 [2] 9d 68 }

  condition:
    any of them
}