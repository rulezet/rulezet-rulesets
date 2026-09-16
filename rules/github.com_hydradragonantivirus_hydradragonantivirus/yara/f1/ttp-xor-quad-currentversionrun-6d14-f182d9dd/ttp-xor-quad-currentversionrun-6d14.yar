rule TTP_XOR_QUAD_CurrentVersionRun_6d14 {
  strings:
    $key_6d14 = { 3e 7b [2] 1a 75 [2] 31 59 [2] 1f 7b [2] 0b 60 [2] 04 7a [2] 1a 67 [2] 18 66 [2] 03 60 [2] 1f 67 [2] 03 48 }

  condition:
    any of them
}