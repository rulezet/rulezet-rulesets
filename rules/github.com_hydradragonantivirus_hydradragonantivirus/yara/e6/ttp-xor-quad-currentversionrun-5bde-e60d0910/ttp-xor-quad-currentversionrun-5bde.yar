rule TTP_XOR_QUAD_CurrentVersionRun_5bde {
  strings:
    $key_5bde = { 08 b1 [2] 2c bf [2] 07 93 [2] 29 b1 [2] 3d aa [2] 32 b0 [2] 2c ad [2] 2e ac [2] 35 aa [2] 29 ad [2] 35 82 }

  condition:
    any of them
}