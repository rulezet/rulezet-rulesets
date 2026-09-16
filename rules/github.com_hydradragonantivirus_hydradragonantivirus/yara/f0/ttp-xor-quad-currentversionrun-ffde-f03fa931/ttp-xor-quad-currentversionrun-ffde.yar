rule TTP_XOR_QUAD_CurrentVersionRun_ffde {
  strings:
    $key_ffde = { ac b1 [2] 88 bf [2] a3 93 [2] 8d b1 [2] 99 aa [2] 96 b0 [2] 88 ad [2] 8a ac [2] 91 aa [2] 8d ad [2] 91 82 }

  condition:
    any of them
}