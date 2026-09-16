rule TTP_XOR_QUAD_CurrentVersionRun_2139 {
  strings:
    $key_2139 = { 72 56 [2] 56 58 [2] 7d 74 [2] 53 56 [2] 47 4d [2] 48 57 [2] 56 4a [2] 54 4b [2] 4f 4d [2] 53 4a [2] 4f 65 }

  condition:
    any of them
}