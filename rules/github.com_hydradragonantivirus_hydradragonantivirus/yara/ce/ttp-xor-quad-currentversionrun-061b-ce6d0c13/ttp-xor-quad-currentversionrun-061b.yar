rule TTP_XOR_QUAD_CurrentVersionRun_061b {
  strings:
    $key_061b = { 55 74 [2] 71 7a [2] 5a 56 [2] 74 74 [2] 60 6f [2] 6f 75 [2] 71 68 [2] 73 69 [2] 68 6f [2] 74 68 [2] 68 47 }

  condition:
    any of them
}