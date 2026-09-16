rule TTP_XOR_QUAD_CurrentVersionRun_17b1 {
  strings:
    $key_17b1 = { 44 de [2] 60 d0 [2] 4b fc [2] 65 de [2] 71 c5 [2] 7e df [2] 60 c2 [2] 62 c3 [2] 79 c5 [2] 65 c2 [2] 79 ed }

  condition:
    any of them
}