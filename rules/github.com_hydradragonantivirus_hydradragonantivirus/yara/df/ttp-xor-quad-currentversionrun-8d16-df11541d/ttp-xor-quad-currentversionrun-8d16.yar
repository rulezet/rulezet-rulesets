rule TTP_XOR_QUAD_CurrentVersionRun_8d16 {
  strings:
    $key_8d16 = { de 79 [2] fa 77 [2] d1 5b [2] ff 79 [2] eb 62 [2] e4 78 [2] fa 65 [2] f8 64 [2] e3 62 [2] ff 65 [2] e3 4a }

  condition:
    any of them
}