rule TTP_XOR_QUAD_CurrentVersionRun_7d3b {
  strings:
    $key_7d3b = { 2e 54 [2] 0a 5a [2] 21 76 [2] 0f 54 [2] 1b 4f [2] 14 55 [2] 0a 48 [2] 08 49 [2] 13 4f [2] 0f 48 [2] 13 67 }

  condition:
    any of them
}