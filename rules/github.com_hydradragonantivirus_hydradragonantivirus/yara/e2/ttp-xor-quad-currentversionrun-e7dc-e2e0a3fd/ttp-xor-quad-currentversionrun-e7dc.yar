rule TTP_XOR_QUAD_CurrentVersionRun_e7dc {
  strings:
    $key_e7dc = { b4 b3 [2] 90 bd [2] bb 91 [2] 95 b3 [2] 81 a8 [2] 8e b2 [2] 90 af [2] 92 ae [2] 89 a8 [2] 95 af [2] 89 80 }

  condition:
    any of them
}