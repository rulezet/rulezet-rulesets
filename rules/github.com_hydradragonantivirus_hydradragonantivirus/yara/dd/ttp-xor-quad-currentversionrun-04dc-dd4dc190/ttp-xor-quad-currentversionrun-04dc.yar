rule TTP_XOR_QUAD_CurrentVersionRun_04dc {
  strings:
    $key_04dc = { 57 b3 [2] 73 bd [2] 58 91 [2] 76 b3 [2] 62 a8 [2] 6d b2 [2] 73 af [2] 71 ae [2] 6a a8 [2] 76 af [2] 6a 80 }

  condition:
    any of them
}