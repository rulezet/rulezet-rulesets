rule TTP_XOR_QUAD_CurrentVersionRun_268a {
  strings:
    $key_268a = { 75 e5 [2] 51 eb [2] 7a c7 [2] 54 e5 [2] 40 fe [2] 4f e4 [2] 51 f9 [2] 53 f8 [2] 48 fe [2] 54 f9 [2] 48 d6 }

  condition:
    any of them
}