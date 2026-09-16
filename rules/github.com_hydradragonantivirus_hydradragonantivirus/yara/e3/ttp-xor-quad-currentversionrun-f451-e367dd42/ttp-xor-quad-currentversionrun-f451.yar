rule TTP_XOR_QUAD_CurrentVersionRun_f451 {
  strings:
    $key_f451 = { a7 3e [2] 83 30 [2] a8 1c [2] 86 3e [2] 92 25 [2] 9d 3f [2] 83 22 [2] 81 23 [2] 9a 25 [2] 86 22 [2] 9a 0d }

  condition:
    any of them
}