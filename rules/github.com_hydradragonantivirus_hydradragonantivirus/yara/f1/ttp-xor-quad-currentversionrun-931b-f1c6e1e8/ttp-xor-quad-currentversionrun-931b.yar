rule TTP_XOR_QUAD_CurrentVersionRun_931b {
  strings:
    $key_931b = { c0 74 [2] e4 7a [2] cf 56 [2] e1 74 [2] f5 6f [2] fa 75 [2] e4 68 [2] e6 69 [2] fd 6f [2] e1 68 [2] fd 47 }

  condition:
    any of them
}