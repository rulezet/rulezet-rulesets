rule TTP_XOR_QUAD_CurrentVersionRun_7614 {
  strings:
    $key_7614 = { 25 7b [2] 01 75 [2] 2a 59 [2] 04 7b [2] 10 60 [2] 1f 7a [2] 01 67 [2] 03 66 [2] 18 60 [2] 04 67 [2] 18 48 }

  condition:
    any of them
}