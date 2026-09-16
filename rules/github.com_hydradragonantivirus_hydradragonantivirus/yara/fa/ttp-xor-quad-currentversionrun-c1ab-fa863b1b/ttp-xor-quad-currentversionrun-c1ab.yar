rule TTP_XOR_QUAD_CurrentVersionRun_c1ab {
  strings:
    $key_c1ab = { 92 c4 [2] b6 ca [2] 9d e6 [2] b3 c4 [2] a7 df [2] a8 c5 [2] b6 d8 [2] b4 d9 [2] af df [2] b3 d8 [2] af f7 }

  condition:
    any of them
}