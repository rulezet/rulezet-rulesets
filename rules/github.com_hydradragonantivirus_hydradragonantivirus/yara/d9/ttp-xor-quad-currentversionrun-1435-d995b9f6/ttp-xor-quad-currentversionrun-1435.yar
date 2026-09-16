rule TTP_XOR_QUAD_CurrentVersionRun_1435 {
  strings:
    $key_1435 = { 47 5a [2] 63 54 [2] 48 78 [2] 66 5a [2] 72 41 [2] 7d 5b [2] 63 46 [2] 61 47 [2] 7a 41 [2] 66 46 [2] 7a 69 }

  condition:
    any of them
}