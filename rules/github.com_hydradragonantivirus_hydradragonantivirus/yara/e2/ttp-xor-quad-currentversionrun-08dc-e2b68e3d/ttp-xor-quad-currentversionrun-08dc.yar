rule TTP_XOR_QUAD_CurrentVersionRun_08dc {
  strings:
    $key_08dc = { 5b b3 [2] 7f bd [2] 54 91 [2] 7a b3 [2] 6e a8 [2] 61 b2 [2] 7f af [2] 7d ae [2] 66 a8 [2] 7a af [2] 66 80 }

  condition:
    any of them
}