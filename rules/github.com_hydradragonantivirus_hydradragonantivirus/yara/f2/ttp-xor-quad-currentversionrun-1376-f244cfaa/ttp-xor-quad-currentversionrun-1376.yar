rule TTP_XOR_QUAD_CurrentVersionRun_1376 {
  strings:
    $key_1376 = { 40 19 [2] 64 17 [2] 4f 3b [2] 61 19 [2] 75 02 [2] 7a 18 [2] 64 05 [2] 66 04 [2] 7d 02 [2] 61 05 [2] 7d 2a }

  condition:
    any of them
}