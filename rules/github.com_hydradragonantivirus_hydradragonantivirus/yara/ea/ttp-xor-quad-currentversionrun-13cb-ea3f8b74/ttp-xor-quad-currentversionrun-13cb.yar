rule TTP_XOR_QUAD_CurrentVersionRun_13cb {
  strings:
    $key_13cb = { 40 a4 [2] 64 aa [2] 4f 86 [2] 61 a4 [2] 75 bf [2] 7a a5 [2] 64 b8 [2] 66 b9 [2] 7d bf [2] 61 b8 [2] 7d 97 }

  condition:
    any of them
}