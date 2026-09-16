rule TTP_XOR_QUAD_CurrentVersionRun_7f14 {
  strings:
    $key_7f14 = { 2c 7b [2] 08 75 [2] 23 59 [2] 0d 7b [2] 19 60 [2] 16 7a [2] 08 67 [2] 0a 66 [2] 11 60 [2] 0d 67 [2] 11 48 }

  condition:
    any of them
}