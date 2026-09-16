rule TTP_XOR_QUAD_CurrentVersionRun_c7dc {
  strings:
    $key_c7dc = { 94 b3 [2] b0 bd [2] 9b 91 [2] b5 b3 [2] a1 a8 [2] ae b2 [2] b0 af [2] b2 ae [2] a9 a8 [2] b5 af [2] a9 80 }

  condition:
    any of them
}