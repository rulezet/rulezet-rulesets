rule TTP_XOR_QUAD_CurrentVersionRun_51aa {
  strings:
    $key_51aa = { 02 c5 [2] 26 cb [2] 0d e7 [2] 23 c5 [2] 37 de [2] 38 c4 [2] 26 d9 [2] 24 d8 [2] 3f de [2] 23 d9 [2] 3f f6 }

  condition:
    any of them
}