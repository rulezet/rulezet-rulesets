rule TTP_XOR_QUAD_CurrentVersionRun_8d0b {
  strings:
    $key_8d0b = { de 64 [2] fa 6a [2] d1 46 [2] ff 64 [2] eb 7f [2] e4 65 [2] fa 78 [2] f8 79 [2] e3 7f [2] ff 78 [2] e3 57 }

  condition:
    any of them
}