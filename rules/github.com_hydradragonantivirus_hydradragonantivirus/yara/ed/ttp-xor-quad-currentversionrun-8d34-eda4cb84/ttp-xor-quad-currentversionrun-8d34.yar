rule TTP_XOR_QUAD_CurrentVersionRun_8d34 {
  strings:
    $key_8d34 = { de 5b [2] fa 55 [2] d1 79 [2] ff 5b [2] eb 40 [2] e4 5a [2] fa 47 [2] f8 46 [2] e3 40 [2] ff 47 [2] e3 68 }

  condition:
    any of them
}