rule TTP_XOR_QUAD_CurrentVersionRun_7cdb {
  strings:
    $key_7cdb = { 2f b4 [2] 0b ba [2] 20 96 [2] 0e b4 [2] 1a af [2] 15 b5 [2] 0b a8 [2] 09 a9 [2] 12 af [2] 0e a8 [2] 12 87 }

  condition:
    any of them
}