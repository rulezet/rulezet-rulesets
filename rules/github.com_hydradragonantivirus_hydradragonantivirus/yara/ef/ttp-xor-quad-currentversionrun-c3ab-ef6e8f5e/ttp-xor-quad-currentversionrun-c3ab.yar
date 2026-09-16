rule TTP_XOR_QUAD_CurrentVersionRun_c3ab {
  strings:
    $key_c3ab = { 90 c4 [2] b4 ca [2] 9f e6 [2] b1 c4 [2] a5 df [2] aa c5 [2] b4 d8 [2] b6 d9 [2] ad df [2] b1 d8 [2] ad f7 }

  condition:
    any of them
}