rule TTP_XOR_QUAD_CurrentVersionRun_7ef8 {
  strings:
    $key_7ef8 = { 2d 97 [2] 09 99 [2] 22 b5 [2] 0c 97 [2] 18 8c [2] 17 96 [2] 09 8b [2] 0b 8a [2] 10 8c [2] 0c 8b [2] 10 a4 }

  condition:
    any of them
}