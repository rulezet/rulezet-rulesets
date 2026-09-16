rule TTP_XOR_QUAD_CurrentVersionRun_2ecc {
  strings:
    $key_2ecc = { 7d a3 [2] 59 ad [2] 72 81 [2] 5c a3 [2] 48 b8 [2] 47 a2 [2] 59 bf [2] 5b be [2] 40 b8 [2] 5c bf [2] 40 90 }

  condition:
    any of them
}