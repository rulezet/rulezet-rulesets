rule TTP_XOR_QUAD_CurrentVersionRun_2d3b {
  strings:
    $key_2d3b = { 7e 54 [2] 5a 5a [2] 71 76 [2] 5f 54 [2] 4b 4f [2] 44 55 [2] 5a 48 [2] 58 49 [2] 43 4f [2] 5f 48 [2] 43 67 }

  condition:
    any of them
}