rule TTP_XOR_QUAD_CurrentVersionRun_20dc {
  strings:
    $key_20dc = { 73 b3 [2] 57 bd [2] 7c 91 [2] 52 b3 [2] 46 a8 [2] 49 b2 [2] 57 af [2] 55 ae [2] 4e a8 [2] 52 af [2] 4e 80 }

  condition:
    any of them
}