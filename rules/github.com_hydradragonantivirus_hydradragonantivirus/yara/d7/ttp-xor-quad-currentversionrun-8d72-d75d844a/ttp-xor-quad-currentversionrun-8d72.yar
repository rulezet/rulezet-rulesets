rule TTP_XOR_QUAD_CurrentVersionRun_8d72 {
  strings:
    $key_8d72 = { de 1d [2] fa 13 [2] d1 3f [2] ff 1d [2] eb 06 [2] e4 1c [2] fa 01 [2] f8 00 [2] e3 06 [2] ff 01 [2] e3 2e }

  condition:
    any of them
}