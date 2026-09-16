rule TTP_XOR_QUAD_CurrentVersionRun_8d74 {
  strings:
    $key_8d74 = { de 1b [2] fa 15 [2] d1 39 [2] ff 1b [2] eb 00 [2] e4 1a [2] fa 07 [2] f8 06 [2] e3 00 [2] ff 07 [2] e3 28 }

  condition:
    any of them
}