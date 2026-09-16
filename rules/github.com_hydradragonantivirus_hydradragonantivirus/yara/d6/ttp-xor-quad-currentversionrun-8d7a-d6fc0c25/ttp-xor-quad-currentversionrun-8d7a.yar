rule TTP_XOR_QUAD_CurrentVersionRun_8d7a {
  strings:
    $key_8d7a = { de 15 [2] fa 1b [2] d1 37 [2] ff 15 [2] eb 0e [2] e4 14 [2] fa 09 [2] f8 08 [2] e3 0e [2] ff 09 [2] e3 26 }

  condition:
    any of them
}