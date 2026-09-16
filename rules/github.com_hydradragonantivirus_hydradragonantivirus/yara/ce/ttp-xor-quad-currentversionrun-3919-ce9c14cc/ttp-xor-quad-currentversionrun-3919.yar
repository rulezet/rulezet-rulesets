rule TTP_XOR_QUAD_CurrentVersionRun_3919 {
  strings:
    $key_3919 = { 6a 76 [2] 4e 78 [2] 65 54 [2] 4b 76 [2] 5f 6d [2] 50 77 [2] 4e 6a [2] 4c 6b [2] 57 6d [2] 4b 6a [2] 57 45 }

  condition:
    any of them
}