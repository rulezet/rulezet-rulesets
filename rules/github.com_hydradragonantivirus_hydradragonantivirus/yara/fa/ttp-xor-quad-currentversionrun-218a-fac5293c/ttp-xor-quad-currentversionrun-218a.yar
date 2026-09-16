rule TTP_XOR_QUAD_CurrentVersionRun_218a {
  strings:
    $key_218a = { 72 e5 [2] 56 eb [2] 7d c7 [2] 53 e5 [2] 47 fe [2] 48 e4 [2] 56 f9 [2] 54 f8 [2] 4f fe [2] 53 f9 [2] 4f d6 }

  condition:
    any of them
}