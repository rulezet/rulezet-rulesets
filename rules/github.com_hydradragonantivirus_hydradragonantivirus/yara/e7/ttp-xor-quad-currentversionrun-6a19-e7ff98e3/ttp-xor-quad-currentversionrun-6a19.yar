rule TTP_XOR_QUAD_CurrentVersionRun_6a19 {
  strings:
    $key_6a19 = { 39 76 [2] 1d 78 [2] 36 54 [2] 18 76 [2] 0c 6d [2] 03 77 [2] 1d 6a [2] 1f 6b [2] 04 6d [2] 18 6a [2] 04 45 }

  condition:
    any of them
}