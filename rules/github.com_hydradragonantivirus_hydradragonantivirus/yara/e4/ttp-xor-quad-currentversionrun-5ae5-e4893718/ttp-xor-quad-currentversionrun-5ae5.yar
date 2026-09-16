rule TTP_XOR_QUAD_CurrentVersionRun_5ae5 {
  strings:
    $key_5ae5 = { 09 8a [2] 2d 84 [2] 06 a8 [2] 28 8a [2] 3c 91 [2] 33 8b [2] 2d 96 [2] 2f 97 [2] 34 91 [2] 28 96 [2] 34 b9 }

  condition:
    any of them
}