rule TTP_XOR_QUAD_CurrentVersionRun_8d53 {
  strings:
    $key_8d53 = { de 3c [2] fa 32 [2] d1 1e [2] ff 3c [2] eb 27 [2] e4 3d [2] fa 20 [2] f8 21 [2] e3 27 [2] ff 20 [2] e3 0f }

  condition:
    any of them
}