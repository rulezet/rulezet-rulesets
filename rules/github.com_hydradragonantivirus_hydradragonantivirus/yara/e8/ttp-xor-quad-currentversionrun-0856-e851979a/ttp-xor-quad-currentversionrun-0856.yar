rule TTP_XOR_QUAD_CurrentVersionRun_0856 {
  strings:
    $key_0856 = { 5b 39 [2] 7f 37 [2] 54 1b [2] 7a 39 [2] 6e 22 [2] 61 38 [2] 7f 25 [2] 7d 24 [2] 66 22 [2] 7a 25 [2] 66 0a }

  condition:
    any of them
}