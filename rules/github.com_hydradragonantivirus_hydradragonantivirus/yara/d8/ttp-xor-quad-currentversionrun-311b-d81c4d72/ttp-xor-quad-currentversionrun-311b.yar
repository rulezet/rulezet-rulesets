rule TTP_XOR_QUAD_CurrentVersionRun_311b {
  strings:
    $key_311b = { 62 74 [2] 46 7a [2] 6d 56 [2] 43 74 [2] 57 6f [2] 58 75 [2] 46 68 [2] 44 69 [2] 5f 6f [2] 43 68 [2] 5f 47 }

  condition:
    any of them
}