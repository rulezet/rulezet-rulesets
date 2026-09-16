rule TTP_XOR_QUAD_CurrentVersionRun_4128 {
  strings:
    $key_4128 = { 12 47 [2] 36 49 [2] 1d 65 [2] 33 47 [2] 27 5c [2] 28 46 [2] 36 5b [2] 34 5a [2] 2f 5c [2] 33 5b [2] 2f 74 }

  condition:
    any of them
}