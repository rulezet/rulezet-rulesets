rule TTP_XOR_QUAD_CurrentVersionRun_5a76 {
  strings:
    $key_5a76 = { 09 19 [2] 2d 17 [2] 06 3b [2] 28 19 [2] 3c 02 [2] 33 18 [2] 2d 05 [2] 2f 04 [2] 34 02 [2] 28 05 [2] 34 2a }

  condition:
    any of them
}