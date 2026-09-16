rule TTP_XOR_QUAD_CurrentVersionRun_6a05 {
  strings:
    $key_6a05 = { 39 6a [2] 1d 64 [2] 36 48 [2] 18 6a [2] 0c 71 [2] 03 6b [2] 1d 76 [2] 1f 77 [2] 04 71 [2] 18 76 [2] 04 59 }

  condition:
    any of them
}