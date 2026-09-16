rule TTP_XOR_QUAD_CurrentVersionRun_e977 {
  strings:
    $key_e977 = { ba 18 [2] 9e 16 [2] b5 3a [2] 9b 18 [2] 8f 03 [2] 80 19 [2] 9e 04 [2] 9c 05 [2] 87 03 [2] 9b 04 [2] 87 2b }

  condition:
    any of them
}