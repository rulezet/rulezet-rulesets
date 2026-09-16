rule TTP_XOR_QUAD_CurrentVersionRun_7314 {
  strings:
    $key_7314 = { 20 7b [2] 04 75 [2] 2f 59 [2] 01 7b [2] 15 60 [2] 1a 7a [2] 04 67 [2] 06 66 [2] 1d 60 [2] 01 67 [2] 1d 48 }

  condition:
    any of them
}