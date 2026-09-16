rule TTP_XOR_QUAD_CurrentVersionRun_93d2 {
  strings:
    $key_93d2 = { c0 bd [2] e4 b3 [2] cf 9f [2] e1 bd [2] f5 a6 [2] fa bc [2] e4 a1 [2] e6 a0 [2] fd a6 [2] e1 a1 [2] fd 8e }

  condition:
    any of them
}