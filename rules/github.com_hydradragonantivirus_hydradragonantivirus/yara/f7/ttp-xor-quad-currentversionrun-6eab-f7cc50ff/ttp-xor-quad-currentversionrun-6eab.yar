rule TTP_XOR_QUAD_CurrentVersionRun_6eab {
  strings:
    $key_6eab = { 3d c4 [2] 19 ca [2] 32 e6 [2] 1c c4 [2] 08 df [2] 07 c5 [2] 19 d8 [2] 1b d9 [2] 00 df [2] 1c d8 [2] 00 f7 }

  condition:
    any of them
}