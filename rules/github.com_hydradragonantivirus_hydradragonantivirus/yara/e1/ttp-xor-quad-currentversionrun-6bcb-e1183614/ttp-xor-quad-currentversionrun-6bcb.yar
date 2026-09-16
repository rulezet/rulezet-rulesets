rule TTP_XOR_QUAD_CurrentVersionRun_6bcb {
  strings:
    $key_6bcb = { 38 a4 [2] 1c aa [2] 37 86 [2] 19 a4 [2] 0d bf [2] 02 a5 [2] 1c b8 [2] 1e b9 [2] 05 bf [2] 19 b8 [2] 05 97 }

  condition:
    any of them
}