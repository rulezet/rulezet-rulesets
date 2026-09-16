rule TTP_XOR_QUAD_CurrentVersionRun_2dbe {
  strings:
    $key_2dbe = { 7e d1 [2] 5a df [2] 71 f3 [2] 5f d1 [2] 4b ca [2] 44 d0 [2] 5a cd [2] 58 cc [2] 43 ca [2] 5f cd [2] 43 e2 }

  condition:
    any of them
}