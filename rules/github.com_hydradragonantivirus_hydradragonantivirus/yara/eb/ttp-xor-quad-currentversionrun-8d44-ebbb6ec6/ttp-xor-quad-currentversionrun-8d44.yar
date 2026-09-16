rule TTP_XOR_QUAD_CurrentVersionRun_8d44 {
  strings:
    $key_8d44 = { de 2b [2] fa 25 [2] d1 09 [2] ff 2b [2] eb 30 [2] e4 2a [2] fa 37 [2] f8 36 [2] e3 30 [2] ff 37 [2] e3 18 }

  condition:
    any of them
}