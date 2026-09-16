rule TTP_XOR_QUAD_CurrentVersionRun_0725 {
  strings:
    $key_0725 = { 54 4a [2] 70 44 [2] 5b 68 [2] 75 4a [2] 61 51 [2] 6e 4b [2] 70 56 [2] 72 57 [2] 69 51 [2] 75 56 [2] 69 79 }

  condition:
    any of them
}