rule TTP_XOR_QUAD_CurrentVersionRun_8d52 {
  strings:
    $key_8d52 = { de 3d [2] fa 33 [2] d1 1f [2] ff 3d [2] eb 26 [2] e4 3c [2] fa 21 [2] f8 20 [2] e3 26 [2] ff 21 [2] e3 0e }

  condition:
    any of them
}