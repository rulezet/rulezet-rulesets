rule TTP_XOR_QUAD_CurrentVersionRun_60dc {
  strings:
    $key_60dc = { 33 b3 [2] 17 bd [2] 3c 91 [2] 12 b3 [2] 06 a8 [2] 09 b2 [2] 17 af [2] 15 ae [2] 0e a8 [2] 12 af [2] 0e 80 }

  condition:
    any of them
}