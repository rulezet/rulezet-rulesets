rule TTP_XOR_QUAD_CurrentVersionRun_35db {
  strings:
    $key_35db = { 66 b4 [2] 42 ba [2] 69 96 [2] 47 b4 [2] 53 af [2] 5c b5 [2] 42 a8 [2] 40 a9 [2] 5b af [2] 47 a8 [2] 5b 87 }

  condition:
    any of them
}