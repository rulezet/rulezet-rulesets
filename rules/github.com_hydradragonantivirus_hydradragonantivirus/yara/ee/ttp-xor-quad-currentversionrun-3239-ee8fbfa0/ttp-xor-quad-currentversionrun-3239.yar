rule TTP_XOR_QUAD_CurrentVersionRun_3239 {
  strings:
    $key_3239 = { 61 56 [2] 45 58 [2] 6e 74 [2] 40 56 [2] 54 4d [2] 5b 57 [2] 45 4a [2] 47 4b [2] 5c 4d [2] 40 4a [2] 5c 65 }

  condition:
    any of them
}