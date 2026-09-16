rule TTP_XOR_QUAD_CurrentVersionRun_7e27 {
  strings:
    $key_7e27 = { 2d 48 [2] 09 46 [2] 22 6a [2] 0c 48 [2] 18 53 [2] 17 49 [2] 09 54 [2] 0b 55 [2] 10 53 [2] 0c 54 [2] 10 7b }

  condition:
    any of them
}