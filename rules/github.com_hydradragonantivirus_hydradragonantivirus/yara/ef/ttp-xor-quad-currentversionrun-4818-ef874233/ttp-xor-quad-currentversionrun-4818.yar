rule TTP_XOR_QUAD_CurrentVersionRun_4818 {
  strings:
    $key_4818 = { 1b 77 [2] 3f 79 [2] 14 55 [2] 3a 77 [2] 2e 6c [2] 21 76 [2] 3f 6b [2] 3d 6a [2] 26 6c [2] 3a 6b [2] 26 44 }

  condition:
    any of them
}