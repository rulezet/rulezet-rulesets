rule TTP_XOR_QUAD_CurrentVersionRun_5756 {
  strings:
    $key_5756 = { 04 39 [2] 20 37 [2] 0b 1b [2] 25 39 [2] 31 22 [2] 3e 38 [2] 20 25 [2] 22 24 [2] 39 22 [2] 25 25 [2] 39 0a }

  condition:
    any of them
}