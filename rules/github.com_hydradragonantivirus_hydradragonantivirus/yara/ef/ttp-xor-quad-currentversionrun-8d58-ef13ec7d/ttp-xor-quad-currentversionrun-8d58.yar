rule TTP_XOR_QUAD_CurrentVersionRun_8d58 {
  strings:
    $key_8d58 = { de 37 [2] fa 39 [2] d1 15 [2] ff 37 [2] eb 2c [2] e4 36 [2] fa 2b [2] f8 2a [2] e3 2c [2] ff 2b [2] e3 04 }

  condition:
    any of them
}