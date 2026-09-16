rule TTP_XOR_QUAD_CurrentVersionRun_8df9 {
  strings:
    $key_8df9 = { de 96 [2] fa 98 [2] d1 b4 [2] ff 96 [2] eb 8d [2] e4 97 [2] fa 8a [2] f8 8b [2] e3 8d [2] ff 8a [2] e3 a5 }

  condition:
    any of them
}