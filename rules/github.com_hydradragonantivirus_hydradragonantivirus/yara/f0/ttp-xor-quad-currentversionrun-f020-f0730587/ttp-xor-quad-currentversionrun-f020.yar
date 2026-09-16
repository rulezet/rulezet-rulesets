rule TTP_XOR_QUAD_CurrentVersionRun_f020 {
  strings:
    $key_f020 = { a3 4f [2] 87 41 [2] ac 6d [2] 82 4f [2] 96 54 [2] 99 4e [2] 87 53 [2] 85 52 [2] 9e 54 [2] 82 53 [2] 9e 7c }

  condition:
    any of them
}