rule TTP_XOR_QUAD_CurrentVersionRun_8d4d {
  strings:
    $key_8d4d = { de 22 [2] fa 2c [2] d1 00 [2] ff 22 [2] eb 39 [2] e4 23 [2] fa 3e [2] f8 3f [2] e3 39 [2] ff 3e [2] e3 11 }

  condition:
    any of them
}