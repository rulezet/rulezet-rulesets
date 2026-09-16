rule TTP_XOR_QUAD_CurrentVersionRun_8dfa {
  strings:
    $key_8dfa = { de 95 [2] fa 9b [2] d1 b7 [2] ff 95 [2] eb 8e [2] e4 94 [2] fa 89 [2] f8 88 [2] e3 8e [2] ff 89 [2] e3 a6 }

  condition:
    any of them
}