rule TTP_XOR_QUAD_CurrentVersionRun_93db {
  strings:
    $key_93db = { c0 b4 [2] e4 ba [2] cf 96 [2] e1 b4 [2] f5 af [2] fa b5 [2] e4 a8 [2] e6 a9 [2] fd af [2] e1 a8 [2] fd 87 }

  condition:
    any of them
}