rule TTP_XOR_QUAD_CurrentVersionRun_5fdb {
  strings:
    $key_5fdb = { 0c b4 [2] 28 ba [2] 03 96 [2] 2d b4 [2] 39 af [2] 36 b5 [2] 28 a8 [2] 2a a9 [2] 31 af [2] 2d a8 [2] 31 87 }

  condition:
    any of them
}