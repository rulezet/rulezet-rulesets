rule TTP_XOR_QUAD_CurrentVersionRun_7828 {
  strings:
    $key_7828 = { 2b 47 [2] 0f 49 [2] 24 65 [2] 0a 47 [2] 1e 5c [2] 11 46 [2] 0f 5b [2] 0d 5a [2] 16 5c [2] 0a 5b [2] 16 74 }

  condition:
    any of them
}