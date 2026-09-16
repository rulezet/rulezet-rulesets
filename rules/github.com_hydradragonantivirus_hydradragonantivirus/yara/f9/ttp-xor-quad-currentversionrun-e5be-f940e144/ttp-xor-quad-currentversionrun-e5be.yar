rule TTP_XOR_QUAD_CurrentVersionRun_e5be {
  strings:
    $key_e5be = { b6 d1 [2] 92 df [2] b9 f3 [2] 97 d1 [2] 83 ca [2] 8c d0 [2] 92 cd [2] 90 cc [2] 8b ca [2] 97 cd [2] 8b e2 }

  condition:
    any of them
}