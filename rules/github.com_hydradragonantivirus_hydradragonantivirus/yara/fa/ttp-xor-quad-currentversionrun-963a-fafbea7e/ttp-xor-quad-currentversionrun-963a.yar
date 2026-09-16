rule TTP_XOR_QUAD_CurrentVersionRun_963a {
  strings:
    $key_963a = { c5 55 [2] e1 5b [2] ca 77 [2] e4 55 [2] f0 4e [2] ff 54 [2] e1 49 [2] e3 48 [2] f8 4e [2] e4 49 [2] f8 66 }

  condition:
    any of them
}