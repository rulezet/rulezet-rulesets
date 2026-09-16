rule TTP_XOR_QUAD_CurrentVersionRun_8d40 {
  strings:
    $key_8d40 = { de 2f [2] fa 21 [2] d1 0d [2] ff 2f [2] eb 34 [2] e4 2e [2] fa 33 [2] f8 32 [2] e3 34 [2] ff 33 [2] e3 1c }

  condition:
    any of them
}