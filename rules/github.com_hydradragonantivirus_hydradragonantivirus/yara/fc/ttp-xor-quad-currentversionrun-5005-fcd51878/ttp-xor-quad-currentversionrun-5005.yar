rule TTP_XOR_QUAD_CurrentVersionRun_5005 {
  strings:
    $key_5005 = { 03 6a [2] 27 64 [2] 0c 48 [2] 22 6a [2] 36 71 [2] 39 6b [2] 27 76 [2] 25 77 [2] 3e 71 [2] 22 76 [2] 3e 59 }

  condition:
    any of them
}