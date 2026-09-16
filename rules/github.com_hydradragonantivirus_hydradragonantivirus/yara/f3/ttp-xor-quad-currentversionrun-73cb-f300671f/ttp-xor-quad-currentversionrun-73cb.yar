rule TTP_XOR_QUAD_CurrentVersionRun_73cb {
  strings:
    $key_73cb = { 20 a4 [2] 04 aa [2] 2f 86 [2] 01 a4 [2] 15 bf [2] 1a a5 [2] 04 b8 [2] 06 b9 [2] 1d bf [2] 01 b8 [2] 1d 97 }

  condition:
    any of them
}