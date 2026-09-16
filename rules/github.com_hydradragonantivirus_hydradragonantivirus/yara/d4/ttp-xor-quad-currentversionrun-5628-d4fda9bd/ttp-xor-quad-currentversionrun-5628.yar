rule TTP_XOR_QUAD_CurrentVersionRun_5628 {
  strings:
    $key_5628 = { 05 47 [2] 21 49 [2] 0a 65 [2] 24 47 [2] 30 5c [2] 3f 46 [2] 21 5b [2] 23 5a [2] 38 5c [2] 24 5b [2] 38 74 }

  condition:
    any of them
}