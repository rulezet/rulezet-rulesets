rule TTP_XOR_QUAD_CurrentVersionRun_9316 {
  strings:
    $key_9316 = { c0 79 [2] e4 77 [2] cf 5b [2] e1 79 [2] f5 62 [2] fa 78 [2] e4 65 [2] e6 64 [2] fd 62 [2] e1 65 [2] fd 4a }

  condition:
    any of them
}