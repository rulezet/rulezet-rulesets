rule TTP_XOR_QUAD_CurrentVersionRun_c0dc {
  strings:
    $key_c0dc = { 93 b3 [2] b7 bd [2] 9c 91 [2] b2 b3 [2] a6 a8 [2] a9 b2 [2] b7 af [2] b5 ae [2] ae a8 [2] b2 af [2] ae 80 }

  condition:
    any of them
}