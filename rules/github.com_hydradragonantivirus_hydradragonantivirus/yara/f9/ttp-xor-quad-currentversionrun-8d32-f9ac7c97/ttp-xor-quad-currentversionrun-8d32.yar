rule TTP_XOR_QUAD_CurrentVersionRun_8d32 {
  strings:
    $key_8d32 = { de 5d [2] fa 53 [2] d1 7f [2] ff 5d [2] eb 46 [2] e4 5c [2] fa 41 [2] f8 40 [2] e3 46 [2] ff 41 [2] e3 6e }

  condition:
    any of them
}