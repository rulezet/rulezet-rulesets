rule TTP_XOR_QUAD_CurrentVersionRun_75db {
  strings:
    $key_75db = { 26 b4 [2] 02 ba [2] 29 96 [2] 07 b4 [2] 13 af [2] 1c b5 [2] 02 a8 [2] 00 a9 [2] 1b af [2] 07 a8 [2] 1b 87 }

  condition:
    any of them
}