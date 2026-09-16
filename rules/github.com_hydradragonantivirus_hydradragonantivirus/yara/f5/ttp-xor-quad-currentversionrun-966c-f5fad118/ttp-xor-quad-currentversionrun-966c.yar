rule TTP_XOR_QUAD_CurrentVersionRun_966c {
  strings:
    $key_966c = { c5 03 [2] e1 0d [2] ca 21 [2] e4 03 [2] f0 18 [2] ff 02 [2] e1 1f [2] e3 1e [2] f8 18 [2] e4 1f [2] f8 30 }

  condition:
    any of them
}