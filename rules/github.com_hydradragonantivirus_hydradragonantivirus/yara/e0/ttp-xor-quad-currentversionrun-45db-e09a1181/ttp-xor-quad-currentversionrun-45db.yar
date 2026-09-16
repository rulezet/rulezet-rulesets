rule TTP_XOR_QUAD_CurrentVersionRun_45db {
  strings:
    $key_45db = { 16 b4 [2] 32 ba [2] 19 96 [2] 37 b4 [2] 23 af [2] 2c b5 [2] 32 a8 [2] 30 a9 [2] 2b af [2] 37 a8 [2] 2b 87 }

  condition:
    any of them
}