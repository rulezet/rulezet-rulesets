rule TTP_XOR_QUAD_CurrentVersionRun_0f45 {
  strings:
    $key_0f45 = { 5c 2a [2] 78 24 [2] 53 08 [2] 7d 2a [2] 69 31 [2] 66 2b [2] 78 36 [2] 7a 37 [2] 61 31 [2] 7d 36 [2] 61 19 }

  condition:
    any of them
}