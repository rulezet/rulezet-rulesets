rule TTP_XOR_QUAD_CurrentVersionRun_4cdb {
  strings:
    $key_4cdb = { 1f b4 [2] 3b ba [2] 10 96 [2] 3e b4 [2] 2a af [2] 25 b5 [2] 3b a8 [2] 39 a9 [2] 22 af [2] 3e a8 [2] 22 87 }

  condition:
    any of them
}