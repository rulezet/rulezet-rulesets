rule TTP_XOR_QUAD_CurrentVersionRun_15ad {
  strings:
    $key_15ad = { 46 c2 [2] 62 cc [2] 49 e0 [2] 67 c2 [2] 73 d9 [2] 7c c3 [2] 62 de [2] 60 df [2] 7b d9 [2] 67 de [2] 7b f1 }

  condition:
    any of them
}