rule TTP_XOR_QUAD_CurrentVersionRun_e2ab {
  strings:
    $key_e2ab = { b1 c4 [2] 95 ca [2] be e6 [2] 90 c4 [2] 84 df [2] 8b c5 [2] 95 d8 [2] 97 d9 [2] 8c df [2] 90 d8 [2] 8c f7 }

  condition:
    any of them
}