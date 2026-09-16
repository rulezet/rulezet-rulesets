rule TTP_XOR_QUAD_CurrentVersionRun_93c1 {
  strings:
    $key_93c1 = { c0 ae [2] e4 a0 [2] cf 8c [2] e1 ae [2] f5 b5 [2] fa af [2] e4 b2 [2] e6 b3 [2] fd b5 [2] e1 b2 [2] fd 9d }

  condition:
    any of them
}