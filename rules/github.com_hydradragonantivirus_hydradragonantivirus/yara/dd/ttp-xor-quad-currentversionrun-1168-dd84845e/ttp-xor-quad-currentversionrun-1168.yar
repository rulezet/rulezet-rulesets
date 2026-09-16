rule TTP_XOR_QUAD_CurrentVersionRun_1168 {
  strings:
    $key_1168 = { 42 07 [2] 66 09 [2] 4d 25 [2] 63 07 [2] 77 1c [2] 78 06 [2] 66 1b [2] 64 1a [2] 7f 1c [2] 63 1b [2] 7f 34 }

  condition:
    any of them
}