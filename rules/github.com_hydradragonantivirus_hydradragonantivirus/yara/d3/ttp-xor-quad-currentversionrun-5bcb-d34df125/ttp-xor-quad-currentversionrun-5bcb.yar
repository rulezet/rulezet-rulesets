rule TTP_XOR_QUAD_CurrentVersionRun_5bcb {
  strings:
    $key_5bcb = { 08 a4 [2] 2c aa [2] 07 86 [2] 29 a4 [2] 3d bf [2] 32 a5 [2] 2c b8 [2] 2e b9 [2] 35 bf [2] 29 b8 [2] 35 97 }

  condition:
    any of them
}