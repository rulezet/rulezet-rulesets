rule TTP_XOR_QUAD_CurrentVersionRun_658a {
  strings:
    $key_658a = { 36 e5 [2] 12 eb [2] 39 c7 [2] 17 e5 [2] 03 fe [2] 0c e4 [2] 12 f9 [2] 10 f8 [2] 0b fe [2] 17 f9 [2] 0b d6 }

  condition:
    any of them
}