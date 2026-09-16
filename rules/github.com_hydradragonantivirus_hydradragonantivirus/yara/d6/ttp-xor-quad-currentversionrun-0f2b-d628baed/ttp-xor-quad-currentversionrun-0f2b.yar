rule TTP_XOR_QUAD_CurrentVersionRun_0f2b {
  strings:
    $key_0f2b = { 5c 44 [2] 78 4a [2] 53 66 [2] 7d 44 [2] 69 5f [2] 66 45 [2] 78 58 [2] 7a 59 [2] 61 5f [2] 7d 58 [2] 61 77 }

  condition:
    any of them
}