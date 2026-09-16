rule TTP_XOR_QUAD_CurrentVersionRun_10be {
  strings:
    $key_10be = { 43 d1 [2] 67 df [2] 4c f3 [2] 62 d1 [2] 76 ca [2] 79 d0 [2] 67 cd [2] 65 cc [2] 7e ca [2] 62 cd [2] 7e e2 }

  condition:
    any of them
}