rule TTP_XOR_QUAD_CurrentVersionRun_2108 {
  strings:
    $key_2108 = { 72 67 [2] 56 69 [2] 7d 45 [2] 53 67 [2] 47 7c [2] 48 66 [2] 56 7b [2] 54 7a [2] 4f 7c [2] 53 7b [2] 4f 54 }

  condition:
    any of them
}