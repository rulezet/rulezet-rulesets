rule TTP_XOR_QUAD_CurrentVersionRun_7e09 {
  strings:
    $key_7e09 = { 2d 66 [2] 09 68 [2] 22 44 [2] 0c 66 [2] 18 7d [2] 17 67 [2] 09 7a [2] 0b 7b [2] 10 7d [2] 0c 7a [2] 10 55 }

  condition:
    any of them
}