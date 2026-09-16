rule TTP_XOR_QUAD_CurrentVersionRun_7acb {
  strings:
    $key_7acb = { 29 a4 [2] 0d aa [2] 26 86 [2] 08 a4 [2] 1c bf [2] 13 a5 [2] 0d b8 [2] 0f b9 [2] 14 bf [2] 08 b8 [2] 14 97 }

  condition:
    any of them
}