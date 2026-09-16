rule TTP_XOR_QUAD_CurrentVersionRun_5a26 {
  strings:
    $key_5a26 = { 09 49 [2] 2d 47 [2] 06 6b [2] 28 49 [2] 3c 52 [2] 33 48 [2] 2d 55 [2] 2f 54 [2] 34 52 [2] 28 55 [2] 34 7a }

  condition:
    any of them
}