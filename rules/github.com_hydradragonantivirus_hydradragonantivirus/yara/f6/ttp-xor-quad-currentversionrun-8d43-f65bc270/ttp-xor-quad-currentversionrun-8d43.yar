rule TTP_XOR_QUAD_CurrentVersionRun_8d43 {
  strings:
    $key_8d43 = { de 2c [2] fa 22 [2] d1 0e [2] ff 2c [2] eb 37 [2] e4 2d [2] fa 30 [2] f8 31 [2] e3 37 [2] ff 30 [2] e3 1f }

  condition:
    any of them
}