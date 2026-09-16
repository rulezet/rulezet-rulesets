rule TTP_XOR_QUAD_CurrentVersionRun_8de9 {
  strings:
    $key_8de9 = { de 86 [2] fa 88 [2] d1 a4 [2] ff 86 [2] eb 9d [2] e4 87 [2] fa 9a [2] f8 9b [2] e3 9d [2] ff 9a [2] e3 b5 }

  condition:
    any of them
}