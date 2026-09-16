rule TTP_XOR_QUAD_CurrentVersionRun_4c54 {
  strings:
    $key_4c54 = { 1f 3b [2] 3b 35 [2] 10 19 [2] 3e 3b [2] 2a 20 [2] 25 3a [2] 3b 27 [2] 39 26 [2] 22 20 [2] 3e 27 [2] 22 08 }

  condition:
    any of them
}