rule TTP_XOR_QUAD_CurrentVersionRun_5126 {
  strings:
    $key_5126 = { 02 49 [2] 26 47 [2] 0d 6b [2] 23 49 [2] 37 52 [2] 38 48 [2] 26 55 [2] 24 54 [2] 3f 52 [2] 23 55 [2] 3f 7a }

  condition:
    any of them
}