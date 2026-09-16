rule TTP_XOR_QUAD_CurrentVersionRun_0f65 {
  strings:
    $key_0f65 = { 5c 0a [2] 78 04 [2] 53 28 [2] 7d 0a [2] 69 11 [2] 66 0b [2] 78 16 [2] 7a 17 [2] 61 11 [2] 7d 16 [2] 61 39 }

  condition:
    any of them
}