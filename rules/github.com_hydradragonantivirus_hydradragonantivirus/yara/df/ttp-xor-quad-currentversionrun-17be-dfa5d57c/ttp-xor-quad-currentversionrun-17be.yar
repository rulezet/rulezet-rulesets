rule TTP_XOR_QUAD_CurrentVersionRun_17be {
  strings:
    $key_17be = { 44 d1 [2] 60 df [2] 4b f3 [2] 65 d1 [2] 71 ca [2] 7e d0 [2] 60 cd [2] 62 cc [2] 79 ca [2] 65 cd [2] 79 e2 }

  condition:
    any of them
}