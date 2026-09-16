rule TTP_XOR_QUAD_CurrentVersionRun_5ebe {
  strings:
    $key_5ebe = { 0d d1 [2] 29 df [2] 02 f3 [2] 2c d1 [2] 38 ca [2] 37 d0 [2] 29 cd [2] 2b cc [2] 30 ca [2] 2c cd [2] 30 e2 }

  condition:
    any of them
}