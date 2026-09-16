rule TTP_XOR_QUAD_CurrentVersionRun_015b {
  strings:
    $key_015b = { 52 34 [2] 76 3a [2] 5d 16 [2] 73 34 [2] 67 2f [2] 68 35 [2] 76 28 [2] 74 29 [2] 6f 2f [2] 73 28 [2] 6f 07 }

  condition:
    any of them
}