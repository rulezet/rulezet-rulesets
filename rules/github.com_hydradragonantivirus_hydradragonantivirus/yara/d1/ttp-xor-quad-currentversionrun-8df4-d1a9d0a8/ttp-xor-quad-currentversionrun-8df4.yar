rule TTP_XOR_QUAD_CurrentVersionRun_8df4 {
  strings:
    $key_8df4 = { de 9b [2] fa 95 [2] d1 b9 [2] ff 9b [2] eb 80 [2] e4 9a [2] fa 87 [2] f8 86 [2] e3 80 [2] ff 87 [2] e3 a8 }

  condition:
    any of them
}