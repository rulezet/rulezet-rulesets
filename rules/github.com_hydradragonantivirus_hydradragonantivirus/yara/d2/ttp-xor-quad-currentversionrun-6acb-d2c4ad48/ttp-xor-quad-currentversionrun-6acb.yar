rule TTP_XOR_QUAD_CurrentVersionRun_6acb {
  strings:
    $key_6acb = { 39 a4 [2] 1d aa [2] 36 86 [2] 18 a4 [2] 0c bf [2] 03 a5 [2] 1d b8 [2] 1f b9 [2] 04 bf [2] 18 b8 [2] 04 97 }

  condition:
    any of them
}