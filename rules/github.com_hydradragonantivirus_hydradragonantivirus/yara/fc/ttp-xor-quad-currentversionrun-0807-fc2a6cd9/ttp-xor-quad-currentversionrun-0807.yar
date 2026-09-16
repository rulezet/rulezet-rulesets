rule TTP_XOR_QUAD_CurrentVersionRun_0807 {
  strings:
    $key_0807 = { 5b 68 [2] 7f 66 [2] 54 4a [2] 7a 68 [2] 6e 73 [2] 61 69 [2] 7f 74 [2] 7d 75 [2] 66 73 [2] 7a 74 [2] 66 5b }

  condition:
    any of them
}