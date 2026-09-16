rule TTP_XOR_QUAD_CurrentVersionRun_3614 {
  strings:
    $key_3614 = { 65 7b [2] 41 75 [2] 6a 59 [2] 44 7b [2] 50 60 [2] 5f 7a [2] 41 67 [2] 43 66 [2] 58 60 [2] 44 67 [2] 58 48 }

  condition:
    any of them
}