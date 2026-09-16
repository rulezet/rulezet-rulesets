rule TTP_XOR_QUAD_CurrentVersionRun_106b {
  strings:
    $key_106b = { 43 04 [2] 67 0a [2] 4c 26 [2] 62 04 [2] 76 1f [2] 79 05 [2] 67 18 [2] 65 19 [2] 7e 1f [2] 62 18 [2] 7e 37 }

  condition:
    any of them
}