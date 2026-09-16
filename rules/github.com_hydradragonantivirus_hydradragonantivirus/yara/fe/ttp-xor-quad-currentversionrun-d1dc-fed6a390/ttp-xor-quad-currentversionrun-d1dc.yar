rule TTP_XOR_QUAD_CurrentVersionRun_d1dc {
  strings:
    $key_d1dc = { 82 b3 [2] a6 bd [2] 8d 91 [2] a3 b3 [2] b7 a8 [2] b8 b2 [2] a6 af [2] a4 ae [2] bf a8 [2] a3 af [2] bf 80 }

  condition:
    any of them
}