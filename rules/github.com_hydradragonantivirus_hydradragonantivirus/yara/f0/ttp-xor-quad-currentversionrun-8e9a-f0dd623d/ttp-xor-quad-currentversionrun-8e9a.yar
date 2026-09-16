rule TTP_XOR_QUAD_CurrentVersionRun_8e9a {
  strings:
    $key_8e9a = { dd f5 [2] f9 fb [2] d2 d7 [2] fc f5 [2] e8 ee [2] e7 f4 [2] f9 e9 [2] fb e8 [2] e0 ee [2] fc e9 [2] e0 c6 }

  condition:
    any of them
}