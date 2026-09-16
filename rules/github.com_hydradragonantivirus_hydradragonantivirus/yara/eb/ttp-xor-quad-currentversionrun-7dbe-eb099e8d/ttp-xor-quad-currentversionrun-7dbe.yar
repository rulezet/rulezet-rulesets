rule TTP_XOR_QUAD_CurrentVersionRun_7dbe {
  strings:
    $key_7dbe = { 2e d1 [2] 0a df [2] 21 f3 [2] 0f d1 [2] 1b ca [2] 14 d0 [2] 0a cd [2] 08 cc [2] 13 ca [2] 0f cd [2] 13 e2 }

  condition:
    any of them
}