rule TTP_XOR_QUAD_CurrentVersionRun_178a {
  strings:
    $key_178a = { 44 e5 [2] 60 eb [2] 4b c7 [2] 65 e5 [2] 71 fe [2] 7e e4 [2] 60 f9 [2] 62 f8 [2] 79 fe [2] 65 f9 [2] 79 d6 }

  condition:
    any of them
}