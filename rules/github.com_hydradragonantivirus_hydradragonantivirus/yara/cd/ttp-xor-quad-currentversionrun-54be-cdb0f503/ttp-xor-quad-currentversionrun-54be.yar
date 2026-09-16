rule TTP_XOR_QUAD_CurrentVersionRun_54be {
  strings:
    $key_54be = { 07 d1 [2] 23 df [2] 08 f3 [2] 26 d1 [2] 32 ca [2] 3d d0 [2] 23 cd [2] 21 cc [2] 3a ca [2] 26 cd [2] 3a e2 }

  condition:
    any of them
}