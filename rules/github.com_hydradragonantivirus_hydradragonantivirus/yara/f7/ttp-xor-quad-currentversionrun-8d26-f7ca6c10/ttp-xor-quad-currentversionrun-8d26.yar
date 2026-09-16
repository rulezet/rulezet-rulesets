rule TTP_XOR_QUAD_CurrentVersionRun_8d26 {
  strings:
    $key_8d26 = { de 49 [2] fa 47 [2] d1 6b [2] ff 49 [2] eb 52 [2] e4 48 [2] fa 55 [2] f8 54 [2] e3 52 [2] ff 55 [2] e3 7a }

  condition:
    any of them
}