rule TTP_XOR_QUAD_CurrentVersionRun_964c {
  strings:
    $key_964c = { c5 23 [2] e1 2d [2] ca 01 [2] e4 23 [2] f0 38 [2] ff 22 [2] e1 3f [2] e3 3e [2] f8 38 [2] e4 3f [2] f8 10 }

  condition:
    any of them
}