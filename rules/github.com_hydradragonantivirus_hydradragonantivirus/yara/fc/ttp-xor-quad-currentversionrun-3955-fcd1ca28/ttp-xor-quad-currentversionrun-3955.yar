rule TTP_XOR_QUAD_CurrentVersionRun_3955 {
  strings:
    $key_3955 = { 6a 3a [2] 4e 34 [2] 65 18 [2] 4b 3a [2] 5f 21 [2] 50 3b [2] 4e 26 [2] 4c 27 [2] 57 21 [2] 4b 26 [2] 57 09 }

  condition:
    any of them
}