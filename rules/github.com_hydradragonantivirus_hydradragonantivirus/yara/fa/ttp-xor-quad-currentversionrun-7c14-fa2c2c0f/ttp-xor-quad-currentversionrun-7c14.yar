rule TTP_XOR_QUAD_CurrentVersionRun_7c14 {
  strings:
    $key_7c14 = { 2f 7b [2] 0b 75 [2] 20 59 [2] 0e 7b [2] 1a 60 [2] 15 7a [2] 0b 67 [2] 09 66 [2] 12 60 [2] 0e 67 [2] 12 48 }

  condition:
    any of them
}