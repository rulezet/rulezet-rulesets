rule TTP_XOR_QUAD_CurrentVersionRun_f37d {
  strings:
    $key_f37d = { a0 12 [2] 84 1c [2] af 30 [2] 81 12 [2] 95 09 [2] 9a 13 [2] 84 0e [2] 86 0f [2] 9d 09 [2] 81 0e [2] 9d 21 }

  condition:
    any of them
}