rule TTP_XOR_QUAD_CurrentVersionRun_0135 {
  strings:
    $key_0135 = { 52 5a [2] 76 54 [2] 5d 78 [2] 73 5a [2] 67 41 [2] 68 5b [2] 76 46 [2] 74 47 [2] 6f 41 [2] 73 46 [2] 6f 69 }

  condition:
    any of them
}