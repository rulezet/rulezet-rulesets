rule TTP_XOR_QUAD_CurrentVersionRun_9340 {
  strings:
    $key_9340 = { c0 2f [2] e4 21 [2] cf 0d [2] e1 2f [2] f5 34 [2] fa 2e [2] e4 33 [2] e6 32 [2] fd 34 [2] e1 33 [2] fd 1c }

  condition:
    any of them
}