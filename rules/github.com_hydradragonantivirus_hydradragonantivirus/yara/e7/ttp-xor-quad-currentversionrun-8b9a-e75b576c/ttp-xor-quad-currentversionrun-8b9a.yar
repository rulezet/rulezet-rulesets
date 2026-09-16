rule TTP_XOR_QUAD_CurrentVersionRun_8b9a {
  strings:
    $key_8b9a = { d8 f5 [2] fc fb [2] d7 d7 [2] f9 f5 [2] ed ee [2] e2 f4 [2] fc e9 [2] fe e8 [2] e5 ee [2] f9 e9 [2] e5 c6 }

  condition:
    any of them
}