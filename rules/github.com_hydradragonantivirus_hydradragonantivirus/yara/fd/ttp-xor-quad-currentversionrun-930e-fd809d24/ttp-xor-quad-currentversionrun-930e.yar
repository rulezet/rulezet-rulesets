rule TTP_XOR_QUAD_CurrentVersionRun_930e {
  strings:
    $key_930e = { c0 61 [2] e4 6f [2] cf 43 [2] e1 61 [2] f5 7a [2] fa 60 [2] e4 7d [2] e6 7c [2] fd 7a [2] e1 7d [2] fd 52 }

  condition:
    any of them
}