rule TTP_XOR_QUAD_CurrentVersionRun_5417 {
  strings:
    $key_5417 = { 07 78 [2] 23 76 [2] 08 5a [2] 26 78 [2] 32 63 [2] 3d 79 [2] 23 64 [2] 21 65 [2] 3a 63 [2] 26 64 [2] 3a 4b }

  condition:
    any of them
}