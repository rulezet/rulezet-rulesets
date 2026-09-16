rule TTP_XOR_QUAD_CurrentVersionRun_3dde {
  strings:
    $key_3dde = { 6e b1 [2] 4a bf [2] 61 93 [2] 4f b1 [2] 5b aa [2] 54 b0 [2] 4a ad [2] 48 ac [2] 53 aa [2] 4f ad [2] 53 82 }

  condition:
    any of them
}