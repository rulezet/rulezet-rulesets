rule TTP_XOR_QUAD_CurrentVersionRun_0bcb {
  strings:
    $key_0bcb = { 58 a4 [2] 7c aa [2] 57 86 [2] 79 a4 [2] 6d bf [2] 62 a5 [2] 7c b8 [2] 7e b9 [2] 65 bf [2] 79 b8 [2] 65 97 }

  condition:
    any of them
}