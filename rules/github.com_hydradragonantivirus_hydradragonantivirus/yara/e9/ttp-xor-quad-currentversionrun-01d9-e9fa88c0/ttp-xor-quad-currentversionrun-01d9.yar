rule TTP_XOR_QUAD_CurrentVersionRun_01d9 {
  strings:
    $key_01d9 = { 52 b6 [2] 76 b8 [2] 5d 94 [2] 73 b6 [2] 67 ad [2] 68 b7 [2] 76 aa [2] 74 ab [2] 6f ad [2] 73 aa [2] 6f 85 }

  condition:
    any of them
}