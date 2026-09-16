rule TTP_XOR_QUAD_CurrentVersionRun_97db {
  strings:
    $key_97db = { c4 b4 [2] e0 ba [2] cb 96 [2] e5 b4 [2] f1 af [2] fe b5 [2] e0 a8 [2] e2 a9 [2] f9 af [2] e5 a8 [2] f9 87 }

  condition:
    any of them
}