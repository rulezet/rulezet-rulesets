rule TTP_XOR_QUAD_CurrentVersionRun_7d56 {
  strings:
    $key_7d56 = { 2e 39 [2] 0a 37 [2] 21 1b [2] 0f 39 [2] 1b 22 [2] 14 38 [2] 0a 25 [2] 08 24 [2] 13 22 [2] 0f 25 [2] 13 0a }

  condition:
    any of them
}