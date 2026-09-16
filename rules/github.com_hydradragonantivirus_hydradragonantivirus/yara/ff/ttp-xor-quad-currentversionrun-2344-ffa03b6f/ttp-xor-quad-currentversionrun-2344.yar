rule TTP_XOR_QUAD_CurrentVersionRun_2344 {
  strings:
    $key_2344 = { 70 2b [2] 54 25 [2] 7f 09 [2] 51 2b [2] 45 30 [2] 4a 2a [2] 54 37 [2] 56 36 [2] 4d 30 [2] 51 37 [2] 4d 18 }

  condition:
    any of them
}