rule TTP_XOR_QUAD_CurrentVersionRun_e4be {
  strings:
    $key_e4be = { b7 d1 [2] 93 df [2] b8 f3 [2] 96 d1 [2] 82 ca [2] 8d d0 [2] 93 cd [2] 91 cc [2] 8a ca [2] 96 cd [2] 8a e2 }

  condition:
    any of them
}