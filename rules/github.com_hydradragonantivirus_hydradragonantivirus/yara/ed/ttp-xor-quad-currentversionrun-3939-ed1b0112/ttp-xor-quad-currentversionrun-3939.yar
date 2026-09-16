rule TTP_XOR_QUAD_CurrentVersionRun_3939 {
  strings:
    $key_3939 = { 6a 56 [2] 4e 58 [2] 65 74 [2] 4b 56 [2] 5f 4d [2] 50 57 [2] 4e 4a [2] 4c 4b [2] 57 4d [2] 4b 4a [2] 57 65 }

  condition:
    any of them
}