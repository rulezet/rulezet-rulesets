rule TTP_XOR_QUAD_CurrentVersionRun_52be {
  strings:
    $key_52be = { 01 d1 [2] 25 df [2] 0e f3 [2] 20 d1 [2] 34 ca [2] 3b d0 [2] 25 cd [2] 27 cc [2] 3c ca [2] 20 cd [2] 3c e2 }

  condition:
    any of them
}