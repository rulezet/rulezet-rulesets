rule TTP_XOR_QUAD_CurrentVersionRun_7835 {
  strings:
    $key_7835 = { 2b 5a [2] 0f 54 [2] 24 78 [2] 0a 5a [2] 1e 41 [2] 11 5b [2] 0f 46 [2] 0d 47 [2] 16 41 [2] 0a 46 [2] 16 69 }

  condition:
    any of them
}