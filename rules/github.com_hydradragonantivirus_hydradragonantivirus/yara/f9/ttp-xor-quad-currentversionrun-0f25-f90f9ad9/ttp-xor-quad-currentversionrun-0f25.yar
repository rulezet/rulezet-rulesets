rule TTP_XOR_QUAD_CurrentVersionRun_0f25 {
  strings:
    $key_0f25 = { 5c 4a [2] 78 44 [2] 53 68 [2] 7d 4a [2] 69 51 [2] 66 4b [2] 78 56 [2] 7a 57 [2] 61 51 [2] 7d 56 [2] 61 79 }

  condition:
    any of them
}