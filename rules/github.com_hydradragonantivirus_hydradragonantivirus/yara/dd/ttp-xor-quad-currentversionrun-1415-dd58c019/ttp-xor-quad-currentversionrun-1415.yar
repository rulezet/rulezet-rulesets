rule TTP_XOR_QUAD_CurrentVersionRun_1415 {
  strings:
    $key_1415 = { 47 7a [2] 63 74 [2] 48 58 [2] 66 7a [2] 72 61 [2] 7d 7b [2] 63 66 [2] 61 67 [2] 7a 61 [2] 66 66 [2] 7a 49 }

  condition:
    any of them
}