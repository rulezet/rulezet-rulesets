rule TTP_XOR_QUAD_CurrentVersionRun_32bf {
  strings:
    $key_32bf = { 61 d0 [2] 45 de [2] 6e f2 [2] 40 d0 [2] 54 cb [2] 5b d1 [2] 45 cc [2] 47 cd [2] 5c cb [2] 40 cc [2] 5c e3 }

  condition:
    any of them
}