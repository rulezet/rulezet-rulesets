rule TTP_XOR_QUAD_CurrentVersionRun_6a24 {
  strings:
    $key_6a24 = { 39 4b [2] 1d 45 [2] 36 69 [2] 18 4b [2] 0c 50 [2] 03 4a [2] 1d 57 [2] 1f 56 [2] 04 50 [2] 18 57 [2] 04 78 }

  condition:
    any of them
}