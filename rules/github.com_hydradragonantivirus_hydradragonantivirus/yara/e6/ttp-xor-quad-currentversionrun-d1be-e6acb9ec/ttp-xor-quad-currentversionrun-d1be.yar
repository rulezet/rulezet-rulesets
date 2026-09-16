rule TTP_XOR_QUAD_CurrentVersionRun_d1be {
  strings:
    $key_d1be = { 82 d1 [2] a6 df [2] 8d f3 [2] a3 d1 [2] b7 ca [2] b8 d0 [2] a6 cd [2] a4 cc [2] bf ca [2] a3 cd [2] bf e2 }

  condition:
    any of them
}