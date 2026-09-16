rule TTP_XOR_QUAD_CurrentVersionRun_008a {
  strings:
    $key_008a = { 53 e5 [2] 77 eb [2] 5c c7 [2] 72 e5 [2] 66 fe [2] 69 e4 [2] 77 f9 [2] 75 f8 [2] 6e fe [2] 72 f9 [2] 6e d6 }

  condition:
    any of them
}