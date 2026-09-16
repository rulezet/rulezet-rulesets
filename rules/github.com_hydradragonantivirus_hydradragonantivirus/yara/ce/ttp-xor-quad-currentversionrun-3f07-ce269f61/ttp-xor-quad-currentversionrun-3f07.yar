rule TTP_XOR_QUAD_CurrentVersionRun_3f07 {
  strings:
    $key_3f07 = { 6c 68 [2] 48 66 [2] 63 4a [2] 4d 68 [2] 59 73 [2] 56 69 [2] 48 74 [2] 4a 75 [2] 51 73 [2] 4d 74 [2] 51 5b }

  condition:
    any of them
}