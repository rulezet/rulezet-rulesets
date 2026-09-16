rule TTP_XOR_QUAD_CurrentVersionRun_47cb {
  strings:
    $key_47cb = { 14 a4 [2] 30 aa [2] 1b 86 [2] 35 a4 [2] 21 bf [2] 2e a5 [2] 30 b8 [2] 32 b9 [2] 29 bf [2] 35 b8 [2] 29 97 }

  condition:
    any of them
}