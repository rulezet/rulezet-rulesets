rule TTP_XOR_QUAD_CurrentVersionRun_3934 {
  strings:
    $key_3934 = { 6a 5b [2] 4e 55 [2] 65 79 [2] 4b 5b [2] 5f 40 [2] 50 5a [2] 4e 47 [2] 4c 46 [2] 57 40 [2] 4b 47 [2] 57 68 }

  condition:
    any of them
}