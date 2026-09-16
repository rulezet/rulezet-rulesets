rule TTP_XOR_QUAD_CurrentVersionRun_65dc {
  strings:
    $key_65dc = { 36 b3 [2] 12 bd [2] 39 91 [2] 17 b3 [2] 03 a8 [2] 0c b2 [2] 12 af [2] 10 ae [2] 0b a8 [2] 17 af [2] 0b 80 }

  condition:
    any of them
}