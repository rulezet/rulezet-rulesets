rule TTP_XOR_QUAD_CurrentVersionRun_965b {
  strings:
    $key_965b = { c5 34 [2] e1 3a [2] ca 16 [2] e4 34 [2] f0 2f [2] ff 35 [2] e1 28 [2] e3 29 [2] f8 2f [2] e4 28 [2] f8 07 }

  condition:
    any of them
}