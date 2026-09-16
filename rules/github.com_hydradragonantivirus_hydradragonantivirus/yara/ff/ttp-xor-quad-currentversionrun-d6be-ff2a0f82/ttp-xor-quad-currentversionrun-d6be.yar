rule TTP_XOR_QUAD_CurrentVersionRun_d6be {
  strings:
    $key_d6be = { 85 d1 [2] a1 df [2] 8a f3 [2] a4 d1 [2] b0 ca [2] bf d0 [2] a1 cd [2] a3 cc [2] b8 ca [2] a4 cd [2] b8 e2 }

  condition:
    any of them
}