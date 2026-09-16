rule TTP_XOR_QUAD_CurrentVersionRun_e1ab {
  strings:
    $key_e1ab = { b2 c4 [2] 96 ca [2] bd e6 [2] 93 c4 [2] 87 df [2] 88 c5 [2] 96 d8 [2] 94 d9 [2] 8f df [2] 93 d8 [2] 8f f7 }

  condition:
    any of them
}