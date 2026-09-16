rule TTP_XOR_QUAD_CurrentVersionRun_64cb {
  strings:
    $key_64cb = { 37 a4 [2] 13 aa [2] 38 86 [2] 16 a4 [2] 02 bf [2] 0d a5 [2] 13 b8 [2] 11 b9 [2] 0a bf [2] 16 b8 [2] 0a 97 }

  condition:
    any of them
}