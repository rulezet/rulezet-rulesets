rule TTP_XOR_QUAD_CurrentVersionRun_9300 {
  strings:
    $key_9300 = { c0 6f [2] e4 61 [2] cf 4d [2] e1 6f [2] f5 74 [2] fa 6e [2] e4 73 [2] e6 72 [2] fd 74 [2] e1 73 [2] fd 5c }

  condition:
    any of them
}