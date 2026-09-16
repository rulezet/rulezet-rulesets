rule TTP_XOR_QUAD_CurrentVersionRun_f78a {
  strings:
    $key_f78a = { a4 e5 [2] 80 eb [2] ab c7 [2] 85 e5 [2] 91 fe [2] 9e e4 [2] 80 f9 [2] 82 f8 [2] 99 fe [2] 85 f9 [2] 99 d6 }

  condition:
    any of them
}