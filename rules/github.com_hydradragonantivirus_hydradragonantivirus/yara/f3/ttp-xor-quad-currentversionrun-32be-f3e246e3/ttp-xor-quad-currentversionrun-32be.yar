rule TTP_XOR_QUAD_CurrentVersionRun_32be {
  strings:
    $key_32be = { 61 d1 [2] 45 df [2] 6e f3 [2] 40 d1 [2] 54 ca [2] 5b d0 [2] 45 cd [2] 47 cc [2] 5c ca [2] 40 cd [2] 5c e2 }

  condition:
    any of them
}