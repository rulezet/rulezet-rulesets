rule TTP_XOR_QUAD_CurrentVersionRun_33bf {
  strings:
    $key_33bf = { 60 d0 [2] 44 de [2] 6f f2 [2] 41 d0 [2] 55 cb [2] 5a d1 [2] 44 cc [2] 46 cd [2] 5d cb [2] 41 cc [2] 5d e3 }

  condition:
    any of them
}