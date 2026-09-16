rule TTP_XOR_QUAD_CurrentVersionRun_0ac0 {
  strings:
    $key_0ac0 = { 59 af [2] 7d a1 [2] 56 8d [2] 78 af [2] 6c b4 [2] 63 ae [2] 7d b3 [2] 7f b2 [2] 64 b4 [2] 78 b3 [2] 64 9c }

  condition:
    any of them
}