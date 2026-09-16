rule TTP_XOR_QUAD_CurrentVersionRun_5ddb {
  strings:
    $key_5ddb = { 0e b4 [2] 2a ba [2] 01 96 [2] 2f b4 [2] 3b af [2] 34 b5 [2] 2a a8 [2] 28 a9 [2] 33 af [2] 2f a8 [2] 33 87 }

  condition:
    any of them
}