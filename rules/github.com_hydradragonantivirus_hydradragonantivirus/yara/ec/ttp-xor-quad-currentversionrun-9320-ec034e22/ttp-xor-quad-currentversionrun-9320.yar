rule TTP_XOR_QUAD_CurrentVersionRun_9320 {
  strings:
    $key_9320 = { c0 4f [2] e4 41 [2] cf 6d [2] e1 4f [2] f5 54 [2] fa 4e [2] e4 53 [2] e6 52 [2] fd 54 [2] e1 53 [2] fd 7c }

  condition:
    any of them
}