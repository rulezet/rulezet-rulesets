rule TTP_XOR_QUAD_CurrentVersionRun_9331 {
  strings:
    $key_9331 = { c0 5e [2] e4 50 [2] cf 7c [2] e1 5e [2] f5 45 [2] fa 5f [2] e4 42 [2] e6 43 [2] fd 45 [2] e1 42 [2] fd 6d }

  condition:
    any of them
}