rule TTP_XOR_QUAD_CurrentVersionRun_9324 {
  strings:
    $key_9324 = { c0 4b [2] e4 45 [2] cf 69 [2] e1 4b [2] f5 50 [2] fa 4a [2] e4 57 [2] e6 56 [2] fd 50 [2] e1 57 [2] fd 78 }

  condition:
    any of them
}