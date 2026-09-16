rule TTP_XOR_QUAD_CurrentVersionRun_8d76 {
  strings:
    $key_8d76 = { de 19 [2] fa 17 [2] d1 3b [2] ff 19 [2] eb 02 [2] e4 18 [2] fa 05 [2] f8 04 [2] e3 02 [2] ff 05 [2] e3 2a }

  condition:
    any of them
}