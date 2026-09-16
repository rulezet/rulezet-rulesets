rule TTP_XOR_QUAD_CurrentVersionRun_11ab {
  strings:
    $key_11ab = { 42 c4 [2] 66 ca [2] 4d e6 [2] 63 c4 [2] 77 df [2] 78 c5 [2] 66 d8 [2] 64 d9 [2] 7f df [2] 63 d8 [2] 7f f7 }

  condition:
    any of them
}