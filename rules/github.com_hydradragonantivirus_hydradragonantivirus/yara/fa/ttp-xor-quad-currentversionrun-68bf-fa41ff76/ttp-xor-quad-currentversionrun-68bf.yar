rule TTP_XOR_QUAD_CurrentVersionRun_68bf {
  strings:
    $key_68bf = { 3b d0 [2] 1f de [2] 34 f2 [2] 1a d0 [2] 0e cb [2] 01 d1 [2] 1f cc [2] 1d cd [2] 06 cb [2] 1a cc [2] 06 e3 }

  condition:
    any of them
}