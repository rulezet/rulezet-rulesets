rule TTP_XOR_QUAD_CurrentVersionRun_6bad {
  strings:
    $key_6bad = { 38 c2 [2] 1c cc [2] 37 e0 [2] 19 c2 [2] 0d d9 [2] 02 c3 [2] 1c de [2] 1e df [2] 05 d9 [2] 19 de [2] 05 f1 }

  condition:
    any of them
}