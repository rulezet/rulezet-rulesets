rule TTP_XOR_QUAD_CurrentVersionRun_77db {
  strings:
    $key_77db = { 24 b4 [2] 00 ba [2] 2b 96 [2] 05 b4 [2] 11 af [2] 1e b5 [2] 00 a8 [2] 02 a9 [2] 19 af [2] 05 a8 [2] 19 87 }

  condition:
    any of them
}