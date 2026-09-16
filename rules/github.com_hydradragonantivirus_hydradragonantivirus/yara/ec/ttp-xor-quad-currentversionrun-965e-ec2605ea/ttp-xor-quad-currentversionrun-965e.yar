rule TTP_XOR_QUAD_CurrentVersionRun_965e {
  strings:
    $key_965e = { c5 31 [2] e1 3f [2] ca 13 [2] e4 31 [2] f0 2a [2] ff 30 [2] e1 2d [2] e3 2c [2] f8 2a [2] e4 2d [2] f8 02 }

  condition:
    any of them
}