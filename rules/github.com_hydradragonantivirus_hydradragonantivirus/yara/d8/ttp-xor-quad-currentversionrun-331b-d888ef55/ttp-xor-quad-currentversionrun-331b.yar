rule TTP_XOR_QUAD_CurrentVersionRun_331b {
  strings:
    $key_331b = { 60 74 [2] 44 7a [2] 6f 56 [2] 41 74 [2] 55 6f [2] 5a 75 [2] 44 68 [2] 46 69 [2] 5d 6f [2] 41 68 [2] 5d 47 }

  condition:
    any of them
}