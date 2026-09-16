rule TTP_XOR_QUAD_CurrentVersionRun_02be {
  strings:
    $key_02be = { 51 d1 [2] 75 df [2] 5e f3 [2] 70 d1 [2] 64 ca [2] 6b d0 [2] 75 cd [2] 77 cc [2] 6c ca [2] 70 cd [2] 6c e2 }

  condition:
    any of them
}