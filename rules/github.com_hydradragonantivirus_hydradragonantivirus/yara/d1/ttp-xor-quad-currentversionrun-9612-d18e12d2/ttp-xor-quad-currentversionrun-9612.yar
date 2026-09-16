rule TTP_XOR_QUAD_CurrentVersionRun_9612 {
  strings:
    $key_9612 = { c5 7d [2] e1 73 [2] ca 5f [2] e4 7d [2] f0 66 [2] ff 7c [2] e1 61 [2] e3 60 [2] f8 66 [2] e4 61 [2] f8 4e }

  condition:
    any of them
}