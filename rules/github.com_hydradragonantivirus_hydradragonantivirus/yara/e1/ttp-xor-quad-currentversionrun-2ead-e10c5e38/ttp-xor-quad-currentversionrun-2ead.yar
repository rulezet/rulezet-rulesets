rule TTP_XOR_QUAD_CurrentVersionRun_2ead {
  strings:
    $key_2ead = { 7d c2 [2] 59 cc [2] 72 e0 [2] 5c c2 [2] 48 d9 [2] 47 c3 [2] 59 de [2] 5b df [2] 40 d9 [2] 5c de [2] 40 f1 }

  condition:
    any of them
}