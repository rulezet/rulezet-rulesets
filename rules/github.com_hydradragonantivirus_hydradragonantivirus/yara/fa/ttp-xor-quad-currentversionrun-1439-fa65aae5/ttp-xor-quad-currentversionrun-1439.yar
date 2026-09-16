rule TTP_XOR_QUAD_CurrentVersionRun_1439 {
  strings:
    $key_1439 = { 47 56 [2] 63 58 [2] 48 74 [2] 66 56 [2] 72 4d [2] 7d 57 [2] 63 4a [2] 61 4b [2] 7a 4d [2] 66 4a [2] 7a 65 }

  condition:
    any of them
}