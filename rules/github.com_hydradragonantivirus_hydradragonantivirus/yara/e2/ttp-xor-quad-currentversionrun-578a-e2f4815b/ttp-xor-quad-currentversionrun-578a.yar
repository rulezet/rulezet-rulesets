rule TTP_XOR_QUAD_CurrentVersionRun_578a {
  strings:
    $key_578a = { 04 e5 [2] 20 eb [2] 0b c7 [2] 25 e5 [2] 31 fe [2] 3e e4 [2] 20 f9 [2] 22 f8 [2] 39 fe [2] 25 f9 [2] 39 d6 }

  condition:
    any of them
}