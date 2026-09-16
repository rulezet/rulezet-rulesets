rule TTP_XOR_QUAD_CurrentVersionRun_9652 {
  strings:
    $key_9652 = { c5 3d [2] e1 33 [2] ca 1f [2] e4 3d [2] f0 26 [2] ff 3c [2] e1 21 [2] e3 20 [2] f8 26 [2] e4 21 [2] f8 0e }

  condition:
    any of them
}