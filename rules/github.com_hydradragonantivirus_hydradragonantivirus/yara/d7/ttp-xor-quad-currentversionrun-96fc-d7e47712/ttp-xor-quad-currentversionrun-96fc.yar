rule TTP_XOR_QUAD_CurrentVersionRun_96fc {
  strings:
    $key_96fc = { c5 93 [2] e1 9d [2] ca b1 [2] e4 93 [2] f0 88 [2] ff 92 [2] e1 8f [2] e3 8e [2] f8 88 [2] e4 8f [2] f8 a0 }

  condition:
    any of them
}