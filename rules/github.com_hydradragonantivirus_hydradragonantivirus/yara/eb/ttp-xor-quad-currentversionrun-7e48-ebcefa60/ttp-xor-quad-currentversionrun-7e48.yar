rule TTP_XOR_QUAD_CurrentVersionRun_7e48 {
  strings:
    $key_7e48 = { 2d 27 [2] 09 29 [2] 22 05 [2] 0c 27 [2] 18 3c [2] 17 26 [2] 09 3b [2] 0b 3a [2] 10 3c [2] 0c 3b [2] 10 14 }

  condition:
    any of them
}