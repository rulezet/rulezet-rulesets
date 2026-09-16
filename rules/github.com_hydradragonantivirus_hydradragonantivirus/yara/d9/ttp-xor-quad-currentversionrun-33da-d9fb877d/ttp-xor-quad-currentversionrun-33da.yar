rule TTP_XOR_QUAD_CurrentVersionRun_33da {
  strings:
    $key_33da = { 60 b5 [2] 44 bb [2] 6f 97 [2] 41 b5 [2] 55 ae [2] 5a b4 [2] 44 a9 [2] 46 a8 [2] 5d ae [2] 41 a9 [2] 5d 86 }

  condition:
    any of them
}