rule TTP_XOR_QUAD_CurrentVersionRun_7e35 {
  strings:
    $key_7e35 = { 2d 5a [2] 09 54 [2] 22 78 [2] 0c 5a [2] 18 41 [2] 17 5b [2] 09 46 [2] 0b 47 [2] 10 41 [2] 0c 46 [2] 10 69 }

  condition:
    any of them
}