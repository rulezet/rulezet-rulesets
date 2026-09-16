rule TTP_XOR_QUAD_CurrentVersionRun_3acb {
  strings:
    $key_3acb = { 69 a4 [2] 4d aa [2] 66 86 [2] 48 a4 [2] 5c bf [2] 53 a5 [2] 4d b8 [2] 4f b9 [2] 54 bf [2] 48 b8 [2] 54 97 }

  condition:
    any of them
}