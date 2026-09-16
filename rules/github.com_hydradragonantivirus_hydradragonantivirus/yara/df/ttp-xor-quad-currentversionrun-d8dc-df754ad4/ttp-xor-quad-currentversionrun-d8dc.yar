rule TTP_XOR_QUAD_CurrentVersionRun_d8dc {
  strings:
    $key_d8dc = { 8b b3 [2] af bd [2] 84 91 [2] aa b3 [2] be a8 [2] b1 b2 [2] af af [2] ad ae [2] b6 a8 [2] aa af [2] b6 80 }

  condition:
    any of them
}