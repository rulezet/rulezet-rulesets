rule TTP_XOR_QUAD_CurrentVersionRun_d9ab {
  strings:
    $key_d9ab = { 8a c4 [2] ae ca [2] 85 e6 [2] ab c4 [2] bf df [2] b0 c5 [2] ae d8 [2] ac d9 [2] b7 df [2] ab d8 [2] b7 f7 }

  condition:
    any of them
}