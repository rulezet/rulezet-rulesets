rule TTP_XOR_QUAD_CurrentVersionRun_f341 {
  strings:
    $key_f341 = { a0 2e [2] 84 20 [2] af 0c [2] 81 2e [2] 95 35 [2] 9a 2f [2] 84 32 [2] 86 33 [2] 9d 35 [2] 81 32 [2] 9d 1d }

  condition:
    any of them
}