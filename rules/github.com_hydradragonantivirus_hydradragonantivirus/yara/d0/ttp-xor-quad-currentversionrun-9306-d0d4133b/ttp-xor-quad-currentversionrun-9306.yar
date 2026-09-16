rule TTP_XOR_QUAD_CurrentVersionRun_9306 {
  strings:
    $key_9306 = { c0 69 [2] e4 67 [2] cf 4b [2] e1 69 [2] f5 72 [2] fa 68 [2] e4 75 [2] e6 74 [2] fd 72 [2] e1 75 [2] fd 5a }

  condition:
    any of them
}