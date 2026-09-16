rule TTP_XOR_QUAD_CurrentVersionRun_2d56 {
  strings:
    $key_2d56 = { 7e 39 [2] 5a 37 [2] 71 1b [2] 5f 39 [2] 4b 22 [2] 44 38 [2] 5a 25 [2] 58 24 [2] 43 22 [2] 5f 25 [2] 43 0a }

  condition:
    any of them
}