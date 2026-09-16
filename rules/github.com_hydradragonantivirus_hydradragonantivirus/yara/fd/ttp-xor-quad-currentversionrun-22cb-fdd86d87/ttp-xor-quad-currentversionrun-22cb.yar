rule TTP_XOR_QUAD_CurrentVersionRun_22cb {
  strings:
    $key_22cb = { 71 a4 [2] 55 aa [2] 7e 86 [2] 50 a4 [2] 44 bf [2] 4b a5 [2] 55 b8 [2] 57 b9 [2] 4c bf [2] 50 b8 [2] 4c 97 }

  condition:
    any of them
}