rule TTP_XOR_QUAD_CurrentVersionRun_23cb {
  strings:
    $key_23cb = { 70 a4 [2] 54 aa [2] 7f 86 [2] 51 a4 [2] 45 bf [2] 4a a5 [2] 54 b8 [2] 56 b9 [2] 4d bf [2] 51 b8 [2] 4d 97 }

  condition:
    any of them
}