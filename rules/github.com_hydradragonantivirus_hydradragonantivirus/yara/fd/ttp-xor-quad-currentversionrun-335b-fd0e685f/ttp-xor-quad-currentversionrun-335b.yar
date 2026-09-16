rule TTP_XOR_QUAD_CurrentVersionRun_335b {
  strings:
    $key_335b = { 60 34 [2] 44 3a [2] 6f 16 [2] 41 34 [2] 55 2f [2] 5a 35 [2] 44 28 [2] 46 29 [2] 5d 2f [2] 41 28 [2] 5d 07 }

  condition:
    any of them
}