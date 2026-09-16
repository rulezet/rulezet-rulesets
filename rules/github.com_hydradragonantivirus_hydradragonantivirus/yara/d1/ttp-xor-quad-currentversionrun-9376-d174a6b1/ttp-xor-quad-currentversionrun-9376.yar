rule TTP_XOR_QUAD_CurrentVersionRun_9376 {
  strings:
    $key_9376 = { c0 19 [2] e4 17 [2] cf 3b [2] e1 19 [2] f5 02 [2] fa 18 [2] e4 05 [2] e6 04 [2] fd 02 [2] e1 05 [2] fd 2a }

  condition:
    any of them
}