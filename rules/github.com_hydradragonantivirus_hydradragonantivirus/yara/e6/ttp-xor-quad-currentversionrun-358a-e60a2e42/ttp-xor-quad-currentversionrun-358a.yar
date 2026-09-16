rule TTP_XOR_QUAD_CurrentVersionRun_358a {
  strings:
    $key_358a = { 66 e5 [2] 42 eb [2] 69 c7 [2] 47 e5 [2] 53 fe [2] 5c e4 [2] 42 f9 [2] 40 f8 [2] 5b fe [2] 47 f9 [2] 5b d6 }

  condition:
    any of them
}