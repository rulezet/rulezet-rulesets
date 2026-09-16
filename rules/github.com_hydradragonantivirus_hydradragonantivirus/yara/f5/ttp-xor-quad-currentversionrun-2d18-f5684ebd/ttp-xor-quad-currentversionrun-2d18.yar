rule TTP_XOR_QUAD_CurrentVersionRun_2d18 {
  strings:
    $key_2d18 = { 7e 77 [2] 5a 79 [2] 71 55 [2] 5f 77 [2] 4b 6c [2] 44 76 [2] 5a 6b [2] 58 6a [2] 43 6c [2] 5f 6b [2] 43 44 }

  condition:
    any of them
}