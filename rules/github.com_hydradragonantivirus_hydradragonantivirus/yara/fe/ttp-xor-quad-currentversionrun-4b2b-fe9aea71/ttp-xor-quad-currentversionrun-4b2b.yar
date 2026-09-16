rule TTP_XOR_QUAD_CurrentVersionRun_4b2b {
  strings:
    $key_4b2b = { 18 44 [2] 3c 4a [2] 17 66 [2] 39 44 [2] 2d 5f [2] 22 45 [2] 3c 58 [2] 3e 59 [2] 25 5f [2] 39 58 [2] 25 77 }

  condition:
    any of them
}