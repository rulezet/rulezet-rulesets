rule TTP_XOR_QUAD_CurrentVersionRun_0fde {
  strings:
    $key_0fde = { 5c b1 [2] 78 bf [2] 53 93 [2] 7d b1 [2] 69 aa [2] 66 b0 [2] 78 ad [2] 7a ac [2] 61 aa [2] 7d ad [2] 61 82 }

  condition:
    any of them
}