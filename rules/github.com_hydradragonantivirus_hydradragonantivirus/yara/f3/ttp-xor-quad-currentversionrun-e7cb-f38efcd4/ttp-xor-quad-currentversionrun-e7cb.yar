rule TTP_XOR_QUAD_CurrentVersionRun_e7cb {
  strings:
    $key_e7cb = { b4 a4 [2] 90 aa [2] bb 86 [2] 95 a4 [2] 81 bf [2] 8e a5 [2] 90 b8 [2] 92 b9 [2] 89 bf [2] 95 b8 [2] 89 97 }

  condition:
    any of them
}