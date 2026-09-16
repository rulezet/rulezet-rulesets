rule TTP_XOR_QUAD_CurrentVersionRun_b0ab {
  strings:
    $key_b0ab = { e3 c4 [2] c7 ca [2] ec e6 [2] c2 c4 [2] d6 df [2] d9 c5 [2] c7 d8 [2] c5 d9 [2] de df [2] c2 d8 [2] de f7 }

  condition:
    any of them
}