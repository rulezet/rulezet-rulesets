rule TTP_XOR_QUAD_CurrentVersionRun_8d64 {
  strings:
    $key_8d64 = { de 0b [2] fa 05 [2] d1 29 [2] ff 0b [2] eb 10 [2] e4 0a [2] fa 17 [2] f8 16 [2] e3 10 [2] ff 17 [2] e3 38 }

  condition:
    any of them
}