rule TTP_XOR_QUAD_CurrentVersionRun_6ebe {
  strings:
    $key_6ebe = { 3d d1 [2] 19 df [2] 32 f3 [2] 1c d1 [2] 08 ca [2] 07 d0 [2] 19 cd [2] 1b cc [2] 00 ca [2] 1c cd [2] 00 e2 }

  condition:
    any of them
}