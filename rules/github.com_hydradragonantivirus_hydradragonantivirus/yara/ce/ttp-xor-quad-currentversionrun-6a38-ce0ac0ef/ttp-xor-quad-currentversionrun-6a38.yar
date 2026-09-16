rule TTP_XOR_QUAD_CurrentVersionRun_6a38 {
  strings:
    $key_6a38 = { 39 57 [2] 1d 59 [2] 36 75 [2] 18 57 [2] 0c 4c [2] 03 56 [2] 1d 4b [2] 1f 4a [2] 04 4c [2] 18 4b [2] 04 64 }

  condition:
    any of them
}