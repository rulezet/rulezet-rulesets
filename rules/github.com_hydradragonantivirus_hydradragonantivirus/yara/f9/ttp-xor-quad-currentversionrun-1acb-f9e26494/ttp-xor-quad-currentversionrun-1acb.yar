rule TTP_XOR_QUAD_CurrentVersionRun_1acb {
  strings:
    $key_1acb = { 49 a4 [2] 6d aa [2] 46 86 [2] 68 a4 [2] 7c bf [2] 73 a5 [2] 6d b8 [2] 6f b9 [2] 74 bf [2] 68 b8 [2] 74 97 }

  condition:
    any of them
}