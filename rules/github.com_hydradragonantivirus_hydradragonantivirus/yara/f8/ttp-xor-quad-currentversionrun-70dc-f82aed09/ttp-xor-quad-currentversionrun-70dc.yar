rule TTP_XOR_QUAD_CurrentVersionRun_70dc {
  strings:
    $key_70dc = { 23 b3 [2] 07 bd [2] 2c 91 [2] 02 b3 [2] 16 a8 [2] 19 b2 [2] 07 af [2] 05 ae [2] 1e a8 [2] 02 af [2] 1e 80 }

  condition:
    any of them
}