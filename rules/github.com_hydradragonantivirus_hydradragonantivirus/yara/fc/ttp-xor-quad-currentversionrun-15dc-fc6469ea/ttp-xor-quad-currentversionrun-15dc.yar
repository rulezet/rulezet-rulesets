rule TTP_XOR_QUAD_CurrentVersionRun_15dc {
  strings:
    $key_15dc = { 46 b3 [2] 62 bd [2] 49 91 [2] 67 b3 [2] 73 a8 [2] 7c b2 [2] 62 af [2] 60 ae [2] 7b a8 [2] 67 af [2] 7b 80 }

  condition:
    any of them
}