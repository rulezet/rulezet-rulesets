rule TTP_XOR_QUAD_CurrentVersionRun_e68a {
  strings:
    $key_e68a = { b5 e5 [2] 91 eb [2] ba c7 [2] 94 e5 [2] 80 fe [2] 8f e4 [2] 91 f9 [2] 93 f8 [2] 88 fe [2] 94 f9 [2] 88 d6 }

  condition:
    any of them
}