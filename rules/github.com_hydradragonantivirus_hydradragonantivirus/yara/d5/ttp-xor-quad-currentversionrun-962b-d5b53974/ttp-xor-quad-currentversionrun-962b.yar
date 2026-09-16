rule TTP_XOR_QUAD_CurrentVersionRun_962b {
  strings:
    $key_962b = { c5 44 [2] e1 4a [2] ca 66 [2] e4 44 [2] f0 5f [2] ff 45 [2] e1 58 [2] e3 59 [2] f8 5f [2] e4 58 [2] f8 77 }

  condition:
    any of them
}