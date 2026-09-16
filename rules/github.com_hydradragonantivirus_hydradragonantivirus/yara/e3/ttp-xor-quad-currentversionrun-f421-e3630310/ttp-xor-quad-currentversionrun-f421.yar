rule TTP_XOR_QUAD_CurrentVersionRun_f421 {
  strings:
    $key_f421 = { a7 4e [2] 83 40 [2] a8 6c [2] 86 4e [2] 92 55 [2] 9d 4f [2] 83 52 [2] 81 53 [2] 9a 55 [2] 86 52 [2] 9a 7d }

  condition:
    any of them
}