rule TTP_XOR_QUAD_CurrentVersionRun_7ac0 {
  strings:
    $key_7ac0 = { 29 af [2] 0d a1 [2] 26 8d [2] 08 af [2] 1c b4 [2] 13 ae [2] 0d b3 [2] 0f b2 [2] 14 b4 [2] 08 b3 [2] 14 9c }

  condition:
    any of them
}