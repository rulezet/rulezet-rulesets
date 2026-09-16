rule TTP_XOR_QUAD_CurrentVersionRun_48cb {
  strings:
    $key_48cb = { 1b a4 [2] 3f aa [2] 14 86 [2] 3a a4 [2] 2e bf [2] 21 a5 [2] 3f b8 [2] 3d b9 [2] 26 bf [2] 3a b8 [2] 26 97 }

  condition:
    any of them
}