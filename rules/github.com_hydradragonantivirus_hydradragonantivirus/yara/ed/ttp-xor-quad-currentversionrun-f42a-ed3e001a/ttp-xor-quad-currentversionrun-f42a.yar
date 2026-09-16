rule TTP_XOR_QUAD_CurrentVersionRun_f42a {
  strings:
    $key_f42a = { a7 45 [2] 83 4b [2] a8 67 [2] 86 45 [2] 92 5e [2] 9d 44 [2] 83 59 [2] 81 58 [2] 9a 5e [2] 86 59 [2] 9a 76 }

  condition:
    any of them
}