rule TTP_XOR_QUAD_CurrentVersionRun_27cb {
  strings:
    $key_27cb = { 74 a4 [2] 50 aa [2] 7b 86 [2] 55 a4 [2] 41 bf [2] 4e a5 [2] 50 b8 [2] 52 b9 [2] 49 bf [2] 55 b8 [2] 49 97 }

  condition:
    any of them
}