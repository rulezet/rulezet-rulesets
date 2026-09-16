rule TTP_XOR_QUAD_CurrentVersionRun_6f34 {
  strings:
    $key_6f34 = { 3c 5b [2] 18 55 [2] 33 79 [2] 1d 5b [2] 09 40 [2] 06 5a [2] 18 47 [2] 1a 46 [2] 01 40 [2] 1d 47 [2] 01 68 }

  condition:
    any of them
}