rule TTP_XOR_QUAD_CurrentVersionRun_128a {
  strings:
    $key_128a = { 41 e5 [2] 65 eb [2] 4e c7 [2] 60 e5 [2] 74 fe [2] 7b e4 [2] 65 f9 [2] 67 f8 [2] 7c fe [2] 60 f9 [2] 7c d6 }

  condition:
    any of them
}