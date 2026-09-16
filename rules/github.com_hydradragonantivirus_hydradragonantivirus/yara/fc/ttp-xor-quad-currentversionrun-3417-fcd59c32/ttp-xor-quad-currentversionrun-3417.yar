rule TTP_XOR_QUAD_CurrentVersionRun_3417 {
  strings:
    $key_3417 = { 67 78 [2] 43 76 [2] 68 5a [2] 46 78 [2] 52 63 [2] 5d 79 [2] 43 64 [2] 41 65 [2] 5a 63 [2] 46 64 [2] 5a 4b }

  condition:
    any of them
}