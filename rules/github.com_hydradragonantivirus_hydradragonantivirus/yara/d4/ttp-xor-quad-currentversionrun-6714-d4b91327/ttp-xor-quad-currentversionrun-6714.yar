rule TTP_XOR_QUAD_CurrentVersionRun_6714 {
  strings:
    $key_6714 = { 34 7b [2] 10 75 [2] 3b 59 [2] 15 7b [2] 01 60 [2] 0e 7a [2] 10 67 [2] 12 66 [2] 09 60 [2] 15 67 [2] 09 48 }

  condition:
    any of them
}