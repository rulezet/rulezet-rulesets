rule TTP_XOR_QUAD_CurrentVersionRun_3128 {
  strings:
    $key_3128 = { 62 47 [2] 46 49 [2] 6d 65 [2] 43 47 [2] 57 5c [2] 58 46 [2] 46 5b [2] 44 5a [2] 5f 5c [2] 43 5b [2] 5f 74 }

  condition:
    any of them
}