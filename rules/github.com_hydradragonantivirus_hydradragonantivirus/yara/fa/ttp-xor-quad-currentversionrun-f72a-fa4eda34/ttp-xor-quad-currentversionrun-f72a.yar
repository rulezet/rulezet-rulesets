rule TTP_XOR_QUAD_CurrentVersionRun_f72a {
  strings:
    $key_f72a = { a4 45 [2] 80 4b [2] ab 67 [2] 85 45 [2] 91 5e [2] 9e 44 [2] 80 59 [2] 82 58 [2] 99 5e [2] 85 59 [2] 99 76 }

  condition:
    any of them
}