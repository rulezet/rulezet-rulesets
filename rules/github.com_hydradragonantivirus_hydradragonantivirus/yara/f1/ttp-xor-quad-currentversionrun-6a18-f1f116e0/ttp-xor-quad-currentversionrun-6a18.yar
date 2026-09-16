rule TTP_XOR_QUAD_CurrentVersionRun_6a18 {
  strings:
    $key_6a18 = { 39 77 [2] 1d 79 [2] 36 55 [2] 18 77 [2] 0c 6c [2] 03 76 [2] 1d 6b [2] 1f 6a [2] 04 6c [2] 18 6b [2] 04 44 }

  condition:
    any of them
}