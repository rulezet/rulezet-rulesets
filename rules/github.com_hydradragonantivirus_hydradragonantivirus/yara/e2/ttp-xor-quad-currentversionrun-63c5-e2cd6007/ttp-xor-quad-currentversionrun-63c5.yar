rule TTP_XOR_QUAD_CurrentVersionRun_63c5 {
  strings:
    $key_63c5 = { 30 aa [2] 14 a4 [2] 3f 88 [2] 11 aa [2] 05 b1 [2] 0a ab [2] 14 b6 [2] 16 b7 [2] 0d b1 [2] 11 b6 [2] 0d 99 }

  condition:
    any of them
}