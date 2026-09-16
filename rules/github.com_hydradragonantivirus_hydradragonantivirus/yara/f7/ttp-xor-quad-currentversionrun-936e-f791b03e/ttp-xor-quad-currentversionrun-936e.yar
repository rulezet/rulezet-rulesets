rule TTP_XOR_QUAD_CurrentVersionRun_936e {
  strings:
    $key_936e = { c0 01 [2] e4 0f [2] cf 23 [2] e1 01 [2] f5 1a [2] fa 00 [2] e4 1d [2] e6 1c [2] fd 1a [2] e1 1d [2] fd 32 }

  condition:
    any of them
}