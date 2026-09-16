rule TTP_XOR_QUAD_CurrentVersionRun_28cb {
  strings:
    $key_28cb = { 7b a4 [2] 5f aa [2] 74 86 [2] 5a a4 [2] 4e bf [2] 41 a5 [2] 5f b8 [2] 5d b9 [2] 46 bf [2] 5a b8 [2] 46 97 }

  condition:
    any of them
}