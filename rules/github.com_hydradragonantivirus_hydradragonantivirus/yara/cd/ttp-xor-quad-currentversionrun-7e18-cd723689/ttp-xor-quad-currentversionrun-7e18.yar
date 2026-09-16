rule TTP_XOR_QUAD_CurrentVersionRun_7e18 {
  strings:
    $key_7e18 = { 2d 77 [2] 09 79 [2] 22 55 [2] 0c 77 [2] 18 6c [2] 17 76 [2] 09 6b [2] 0b 6a [2] 10 6c [2] 0c 6b [2] 10 44 }

  condition:
    any of them
}