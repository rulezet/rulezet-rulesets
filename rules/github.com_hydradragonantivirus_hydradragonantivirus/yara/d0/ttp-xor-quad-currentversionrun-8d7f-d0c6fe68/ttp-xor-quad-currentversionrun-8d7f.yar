rule TTP_XOR_QUAD_CurrentVersionRun_8d7f {
  strings:
    $key_8d7f = { de 10 [2] fa 1e [2] d1 32 [2] ff 10 [2] eb 0b [2] e4 11 [2] fa 0c [2] f8 0d [2] e3 0b [2] ff 0c [2] e3 23 }

  condition:
    any of them
}