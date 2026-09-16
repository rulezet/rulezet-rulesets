rule TTP_XOR_QUAD_CurrentVersionRun_8d5a {
  strings:
    $key_8d5a = { de 35 [2] fa 3b [2] d1 17 [2] ff 35 [2] eb 2e [2] e4 34 [2] fa 29 [2] f8 28 [2] e3 2e [2] ff 29 [2] e3 06 }

  condition:
    any of them
}