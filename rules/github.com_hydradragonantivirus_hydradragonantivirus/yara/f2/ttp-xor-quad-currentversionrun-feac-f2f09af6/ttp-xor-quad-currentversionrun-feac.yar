rule TTP_XOR_QUAD_CurrentVersionRun_feac {
  strings:
    $key_feac = { ad c3 [2] 89 cd [2] a2 e1 [2] 8c c3 [2] 98 d8 [2] 97 c2 [2] 89 df [2] 8b de [2] 90 d8 [2] 8c df [2] 90 f0 }

  condition:
    any of them
}