rule TTP_XOR_QUAD_CurrentVersionRun_eebe {
  strings:
    $key_eebe = { bd d1 [2] 99 df [2] b2 f3 [2] 9c d1 [2] 88 ca [2] 87 d0 [2] 99 cd [2] 9b cc [2] 80 ca [2] 9c cd [2] 80 e2 }

  condition:
    any of them
}