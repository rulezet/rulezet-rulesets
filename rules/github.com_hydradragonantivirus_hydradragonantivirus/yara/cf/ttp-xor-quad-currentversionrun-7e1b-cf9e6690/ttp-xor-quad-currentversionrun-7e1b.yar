rule TTP_XOR_QUAD_CurrentVersionRun_7e1b {
  strings:
    $key_7e1b = { 2d 74 [2] 09 7a [2] 22 56 [2] 0c 74 [2] 18 6f [2] 17 75 [2] 09 68 [2] 0b 69 [2] 10 6f [2] 0c 68 [2] 10 47 }

  condition:
    any of them
}