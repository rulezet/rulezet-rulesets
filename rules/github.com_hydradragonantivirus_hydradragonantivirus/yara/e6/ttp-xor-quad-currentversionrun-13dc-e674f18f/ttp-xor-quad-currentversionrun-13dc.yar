rule TTP_XOR_QUAD_CurrentVersionRun_13dc {
  strings:
    $key_13dc = { 40 b3 [2] 64 bd [2] 4f 91 [2] 61 b3 [2] 75 a8 [2] 7a b2 [2] 64 af [2] 66 ae [2] 7d a8 [2] 61 af [2] 7d 80 }

  condition:
    any of them
}