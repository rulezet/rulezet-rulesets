rule TTP_XOR_QUAD_CurrentVersionRun_1335 {
  strings:
    $key_1335 = { 40 5a [2] 64 54 [2] 4f 78 [2] 61 5a [2] 75 41 [2] 7a 5b [2] 64 46 [2] 66 47 [2] 7d 41 [2] 61 46 [2] 7d 69 }

  condition:
    any of them
}