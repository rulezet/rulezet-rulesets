rule TTP_XOR_QUAD_CurrentVersionRun_f71a {
  strings:
    $key_f71a = { a4 75 [2] 80 7b [2] ab 57 [2] 85 75 [2] 91 6e [2] 9e 74 [2] 80 69 [2] 82 68 [2] 99 6e [2] 85 69 [2] 99 46 }

  condition:
    any of them
}