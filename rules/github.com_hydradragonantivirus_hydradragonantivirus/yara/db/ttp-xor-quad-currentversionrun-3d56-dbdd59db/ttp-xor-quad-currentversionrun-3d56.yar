rule TTP_XOR_QUAD_CurrentVersionRun_3d56 {
  strings:
    $key_3d56 = { 6e 39 [2] 4a 37 [2] 61 1b [2] 4f 39 [2] 5b 22 [2] 54 38 [2] 4a 25 [2] 48 24 [2] 53 22 [2] 4f 25 [2] 53 0a }

  condition:
    any of them
}