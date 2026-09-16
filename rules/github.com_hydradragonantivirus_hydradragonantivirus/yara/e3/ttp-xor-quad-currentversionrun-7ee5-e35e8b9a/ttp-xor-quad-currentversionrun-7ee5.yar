rule TTP_XOR_QUAD_CurrentVersionRun_7ee5 {
  strings:
    $key_7ee5 = { 2d 8a [2] 09 84 [2] 22 a8 [2] 0c 8a [2] 18 91 [2] 17 8b [2] 09 96 [2] 0b 97 [2] 10 91 [2] 0c 96 [2] 10 b9 }

  condition:
    any of them
}