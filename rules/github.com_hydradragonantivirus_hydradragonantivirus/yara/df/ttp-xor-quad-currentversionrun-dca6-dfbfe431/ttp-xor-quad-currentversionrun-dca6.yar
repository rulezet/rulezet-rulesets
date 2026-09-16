rule TTP_XOR_QUAD_CurrentVersionRun_dca6 {
  strings:
    $key_dca6 = { 8f c9 [2] ab c7 [2] 80 eb [2] ae c9 [2] ba d2 [2] b5 c8 [2] ab d5 [2] a9 d4 [2] b2 d2 [2] ae d5 [2] b2 fa }

  condition:
    any of them
}