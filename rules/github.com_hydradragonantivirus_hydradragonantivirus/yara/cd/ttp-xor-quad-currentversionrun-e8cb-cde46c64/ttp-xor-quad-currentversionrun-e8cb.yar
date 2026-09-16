rule TTP_XOR_QUAD_CurrentVersionRun_e8cb {
  strings:
    $key_e8cb = { bb a4 [2] 9f aa [2] b4 86 [2] 9a a4 [2] 8e bf [2] 81 a5 [2] 9f b8 [2] 9d b9 [2] 86 bf [2] 9a b8 [2] 86 97 }

  condition:
    any of them
}