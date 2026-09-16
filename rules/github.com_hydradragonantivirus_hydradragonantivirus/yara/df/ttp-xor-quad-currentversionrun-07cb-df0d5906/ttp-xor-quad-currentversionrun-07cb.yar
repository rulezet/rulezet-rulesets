rule TTP_XOR_QUAD_CurrentVersionRun_07cb {
  strings:
    $key_07cb = { 54 a4 [2] 70 aa [2] 5b 86 [2] 75 a4 [2] 61 bf [2] 6e a5 [2] 70 b8 [2] 72 b9 [2] 69 bf [2] 75 b8 [2] 69 97 }

  condition:
    any of them
}