rule TTP_XOR_QUAD_CurrentVersionRun_1456 {
  strings:
    $key_1456 = { 47 39 [2] 63 37 [2] 48 1b [2] 66 39 [2] 72 22 [2] 7d 38 [2] 63 25 [2] 61 24 [2] 7a 22 [2] 66 25 [2] 7a 0a }

  condition:
    any of them
}