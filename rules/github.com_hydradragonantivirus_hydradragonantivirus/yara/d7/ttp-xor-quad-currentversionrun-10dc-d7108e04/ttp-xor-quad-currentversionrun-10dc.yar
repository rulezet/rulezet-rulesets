rule TTP_XOR_QUAD_CurrentVersionRun_10dc {
  strings:
    $key_10dc = { 43 b3 [2] 67 bd [2] 4c 91 [2] 62 b3 [2] 76 a8 [2] 79 b2 [2] 67 af [2] 65 ae [2] 7e a8 [2] 62 af [2] 7e 80 }

  condition:
    any of them
}