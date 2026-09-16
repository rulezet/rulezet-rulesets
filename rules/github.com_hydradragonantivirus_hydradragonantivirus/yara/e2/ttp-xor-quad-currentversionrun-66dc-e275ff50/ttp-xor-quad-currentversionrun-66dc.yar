rule TTP_XOR_QUAD_CurrentVersionRun_66dc {
  strings:
    $key_66dc = { 35 b3 [2] 11 bd [2] 3a 91 [2] 14 b3 [2] 00 a8 [2] 0f b2 [2] 11 af [2] 13 ae [2] 08 a8 [2] 14 af [2] 08 80 }

  condition:
    any of them
}