rule TTP_XOR_QUAD_CurrentVersionRun_7976 {
  strings:
    $key_7976 = { 2a 19 [2] 0e 17 [2] 25 3b [2] 0b 19 [2] 1f 02 [2] 10 18 [2] 0e 05 [2] 0c 04 [2] 17 02 [2] 0b 05 [2] 17 2a }

  condition:
    any of them
}