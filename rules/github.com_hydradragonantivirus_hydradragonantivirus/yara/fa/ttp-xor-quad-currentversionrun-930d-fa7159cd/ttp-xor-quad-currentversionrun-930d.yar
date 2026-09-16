rule TTP_XOR_QUAD_CurrentVersionRun_930d {
  strings:
    $key_930d = { c0 62 [2] e4 6c [2] cf 40 [2] e1 62 [2] f5 79 [2] fa 63 [2] e4 7e [2] e6 7f [2] fd 79 [2] e1 7e [2] fd 51 }

  condition:
    any of them
}