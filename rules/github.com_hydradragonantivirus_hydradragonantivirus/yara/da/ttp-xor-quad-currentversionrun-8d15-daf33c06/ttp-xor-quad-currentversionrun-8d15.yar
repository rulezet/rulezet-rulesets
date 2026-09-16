rule TTP_XOR_QUAD_CurrentVersionRun_8d15 {
  strings:
    $key_8d15 = { de 7a [2] fa 74 [2] d1 58 [2] ff 7a [2] eb 61 [2] e4 7b [2] fa 66 [2] f8 67 [2] e3 61 [2] ff 66 [2] e3 49 }

  condition:
    any of them
}