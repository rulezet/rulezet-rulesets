rule TTP_XOR_QUAD_CurrentVersionRun_8e8a {
  strings:
    $key_8e8a = { dd e5 [2] f9 eb [2] d2 c7 [2] fc e5 [2] e8 fe [2] e7 e4 [2] f9 f9 [2] fb f8 [2] e0 fe [2] fc f9 [2] e0 d6 }

  condition:
    any of them
}