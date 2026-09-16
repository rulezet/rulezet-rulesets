rule TTP_XOR_QUAD_CurrentVersionRun_8d50 {
  strings:
    $key_8d50 = { de 3f [2] fa 31 [2] d1 1d [2] ff 3f [2] eb 24 [2] e4 3e [2] fa 23 [2] f8 22 [2] e3 24 [2] ff 23 [2] e3 0c }

  condition:
    any of them
}