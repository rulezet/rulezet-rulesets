rule TTP_XOR_QUAD_CurrentVersionRun_4fde {
  strings:
    $key_4fde = { 1c b1 [2] 38 bf [2] 13 93 [2] 3d b1 [2] 29 aa [2] 26 b0 [2] 38 ad [2] 3a ac [2] 21 aa [2] 3d ad [2] 21 82 }

  condition:
    any of them
}