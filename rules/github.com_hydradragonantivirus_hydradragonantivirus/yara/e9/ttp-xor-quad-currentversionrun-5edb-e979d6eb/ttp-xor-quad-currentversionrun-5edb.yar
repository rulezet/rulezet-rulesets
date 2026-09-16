rule TTP_XOR_QUAD_CurrentVersionRun_5edb {
  strings:
    $key_5edb = { 0d b4 [2] 29 ba [2] 02 96 [2] 2c b4 [2] 38 af [2] 37 b5 [2] 29 a8 [2] 2b a9 [2] 30 af [2] 2c a8 [2] 30 87 }

  condition:
    any of them
}