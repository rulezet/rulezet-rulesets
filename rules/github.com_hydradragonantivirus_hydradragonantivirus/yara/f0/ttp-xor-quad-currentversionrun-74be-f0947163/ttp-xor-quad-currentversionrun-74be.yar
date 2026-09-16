rule TTP_XOR_QUAD_CurrentVersionRun_74be {
  strings:
    $key_74be = { 27 d1 [2] 03 df [2] 28 f3 [2] 06 d1 [2] 12 ca [2] 1d d0 [2] 03 cd [2] 01 cc [2] 1a ca [2] 06 cd [2] 1a e2 }

  condition:
    any of them
}