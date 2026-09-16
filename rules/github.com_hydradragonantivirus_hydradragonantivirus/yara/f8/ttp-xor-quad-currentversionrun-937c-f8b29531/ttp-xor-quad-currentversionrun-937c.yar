rule TTP_XOR_QUAD_CurrentVersionRun_937c {
  strings:
    $key_937c = { c0 13 [2] e4 1d [2] cf 31 [2] e1 13 [2] f5 08 [2] fa 12 [2] e4 0f [2] e6 0e [2] fd 08 [2] e1 0f [2] fd 20 }

  condition:
    any of them
}