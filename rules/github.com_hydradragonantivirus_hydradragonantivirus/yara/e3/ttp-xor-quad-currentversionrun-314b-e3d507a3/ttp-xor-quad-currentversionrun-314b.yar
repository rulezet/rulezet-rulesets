rule TTP_XOR_QUAD_CurrentVersionRun_314b {
  strings:
    $key_314b = { 62 24 [2] 46 2a [2] 6d 06 [2] 43 24 [2] 57 3f [2] 58 25 [2] 46 38 [2] 44 39 [2] 5f 3f [2] 43 38 [2] 5f 17 }

  condition:
    any of them
}