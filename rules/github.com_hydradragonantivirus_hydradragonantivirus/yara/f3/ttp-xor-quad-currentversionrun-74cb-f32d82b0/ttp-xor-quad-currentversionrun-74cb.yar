rule TTP_XOR_QUAD_CurrentVersionRun_74cb {
  strings:
    $key_74cb = { 27 a4 [2] 03 aa [2] 28 86 [2] 06 a4 [2] 12 bf [2] 1d a5 [2] 03 b8 [2] 01 b9 [2] 1a bf [2] 06 b8 [2] 1a 97 }

  condition:
    any of them
}