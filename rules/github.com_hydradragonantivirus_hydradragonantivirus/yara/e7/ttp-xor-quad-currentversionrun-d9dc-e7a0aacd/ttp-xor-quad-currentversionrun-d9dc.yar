rule TTP_XOR_QUAD_CurrentVersionRun_d9dc {
  strings:
    $key_d9dc = { 8a b3 [2] ae bd [2] 85 91 [2] ab b3 [2] bf a8 [2] b0 b2 [2] ae af [2] ac ae [2] b7 a8 [2] ab af [2] b7 80 }

  condition:
    any of them
}