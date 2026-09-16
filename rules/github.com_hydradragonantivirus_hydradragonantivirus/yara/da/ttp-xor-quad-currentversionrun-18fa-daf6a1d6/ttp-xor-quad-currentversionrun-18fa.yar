rule TTP_XOR_QUAD_CurrentVersionRun_18fa {
  strings:
    $key_18fa = { 4b 95 [2] 6f 9b [2] 44 b7 [2] 6a 95 [2] 7e 8e [2] 71 94 [2] 6f 89 [2] 6d 88 [2] 76 8e [2] 6a 89 [2] 76 a6 }

  condition:
    any of them
}