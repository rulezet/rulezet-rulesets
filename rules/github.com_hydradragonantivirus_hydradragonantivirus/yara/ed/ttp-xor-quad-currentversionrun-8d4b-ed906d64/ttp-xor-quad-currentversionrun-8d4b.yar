rule TTP_XOR_QUAD_CurrentVersionRun_8d4b {
  strings:
    $key_8d4b = { de 24 [2] fa 2a [2] d1 06 [2] ff 24 [2] eb 3f [2] e4 25 [2] fa 38 [2] f8 39 [2] e3 3f [2] ff 38 [2] e3 17 }

  condition:
    any of them
}