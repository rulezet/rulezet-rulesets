rule TTP_XOR_QUAD_CurrentVersionRun_508a {
  strings:
    $key_508a = { 03 e5 [2] 27 eb [2] 0c c7 [2] 22 e5 [2] 36 fe [2] 39 e4 [2] 27 f9 [2] 25 f8 [2] 3e fe [2] 22 f9 [2] 3e d6 }

  condition:
    any of them
}