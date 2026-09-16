rule TTP_XOR_QUAD_CurrentVersionRun_3924 {
  strings:
    $key_3924 = { 6a 4b [2] 4e 45 [2] 65 69 [2] 4b 4b [2] 5f 50 [2] 50 4a [2] 4e 57 [2] 4c 56 [2] 57 50 [2] 4b 57 [2] 57 78 }

  condition:
    any of them
}