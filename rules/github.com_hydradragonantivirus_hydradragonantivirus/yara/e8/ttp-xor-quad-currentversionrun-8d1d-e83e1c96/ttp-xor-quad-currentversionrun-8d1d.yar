rule TTP_XOR_QUAD_CurrentVersionRun_8d1d {
  strings:
    $key_8d1d = { de 72 [2] fa 7c [2] d1 50 [2] ff 72 [2] eb 69 [2] e4 73 [2] fa 6e [2] f8 6f [2] e3 69 [2] ff 6e [2] e3 41 }

  condition:
    any of them
}