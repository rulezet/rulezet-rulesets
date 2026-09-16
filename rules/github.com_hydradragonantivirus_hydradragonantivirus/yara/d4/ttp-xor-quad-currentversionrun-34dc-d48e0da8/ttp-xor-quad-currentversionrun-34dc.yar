rule TTP_XOR_QUAD_CurrentVersionRun_34dc {
  strings:
    $key_34dc = { 67 b3 [2] 43 bd [2] 68 91 [2] 46 b3 [2] 52 a8 [2] 5d b2 [2] 43 af [2] 41 ae [2] 5a a8 [2] 46 af [2] 5a 80 }

  condition:
    any of them
}