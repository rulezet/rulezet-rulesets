rule TTP_XOR_QUAD_CurrentVersionRun_32dc {
  strings:
    $key_32dc = { 61 b3 [2] 45 bd [2] 6e 91 [2] 40 b3 [2] 54 a8 [2] 5b b2 [2] 45 af [2] 47 ae [2] 5c a8 [2] 40 af [2] 5c 80 }

  condition:
    any of them
}