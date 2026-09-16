rule TTP_XOR_QUAD_CurrentVersionRun_4417 {
  strings:
    $key_4417 = { 17 78 [2] 33 76 [2] 18 5a [2] 36 78 [2] 22 63 [2] 2d 79 [2] 33 64 [2] 31 65 [2] 2a 63 [2] 36 64 [2] 2a 4b }

  condition:
    any of them
}