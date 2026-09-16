rule TTP_XOR_QUAD_CurrentVersionRun_3126 {
  strings:
    $key_3126 = { 62 49 [2] 46 47 [2] 6d 6b [2] 43 49 [2] 57 52 [2] 58 48 [2] 46 55 [2] 44 54 [2] 5f 52 [2] 43 55 [2] 5f 7a }

  condition:
    any of them
}