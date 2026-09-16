rule TTP_XOR_QUAD_CurrentVersionRun_10db {
  strings:
    $key_10db = { 43 b4 [2] 67 ba [2] 4c 96 [2] 62 b4 [2] 76 af [2] 79 b5 [2] 67 a8 [2] 65 a9 [2] 7e af [2] 62 a8 [2] 7e 87 }

  condition:
    any of them
}