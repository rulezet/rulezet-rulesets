rule TTP_XOR_QUAD_CurrentVersionRun_50c5 {
  strings:
    $key_50c5 = { 03 aa [2] 27 a4 [2] 0c 88 [2] 22 aa [2] 36 b1 [2] 39 ab [2] 27 b6 [2] 25 b7 [2] 3e b1 [2] 22 b6 [2] 3e 99 }

  condition:
    any of them
}