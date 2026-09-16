rule TTP_XOR_QUAD_CurrentVersionRun_8d33 {
  strings:
    $key_8d33 = { de 5c [2] fa 52 [2] d1 7e [2] ff 5c [2] eb 47 [2] e4 5d [2] fa 40 [2] f8 41 [2] e3 47 [2] ff 40 [2] e3 6f }

  condition:
    any of them
}