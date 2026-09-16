rule TTP_XOR_QUAD_CurrentVersionRun_9304 {
  strings:
    $key_9304 = { c0 6b [2] e4 65 [2] cf 49 [2] e1 6b [2] f5 70 [2] fa 6a [2] e4 77 [2] e6 76 [2] fd 70 [2] e1 77 [2] fd 58 }

  condition:
    any of them
}