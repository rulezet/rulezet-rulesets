rule TTP_XOR_QUAD_CurrentVersionRun_55be {
  strings:
    $key_55be = { 06 d1 [2] 22 df [2] 09 f3 [2] 27 d1 [2] 33 ca [2] 3c d0 [2] 22 cd [2] 20 cc [2] 3b ca [2] 27 cd [2] 3b e2 }

  condition:
    any of them
}