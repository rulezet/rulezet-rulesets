rule TTP_XOR_QUAD_CurrentVersionRun_1418 {
  strings:
    $key_1418 = { 47 77 [2] 63 79 [2] 48 55 [2] 66 77 [2] 72 6c [2] 7d 76 [2] 63 6b [2] 61 6a [2] 7a 6c [2] 66 6b [2] 7a 44 }

  condition:
    any of them
}