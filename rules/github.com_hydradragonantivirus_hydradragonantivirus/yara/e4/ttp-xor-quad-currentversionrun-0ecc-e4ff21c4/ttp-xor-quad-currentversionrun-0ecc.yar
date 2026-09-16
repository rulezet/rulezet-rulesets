rule TTP_XOR_QUAD_CurrentVersionRun_0ecc {
  strings:
    $key_0ecc = { 5d a3 [2] 79 ad [2] 52 81 [2] 7c a3 [2] 68 b8 [2] 67 a2 [2] 79 bf [2] 7b be [2] 60 b8 [2] 7c bf [2] 60 90 }

  condition:
    any of them
}