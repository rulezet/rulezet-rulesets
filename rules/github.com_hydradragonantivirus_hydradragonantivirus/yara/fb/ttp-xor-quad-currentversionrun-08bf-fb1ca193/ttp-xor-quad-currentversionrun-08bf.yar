rule TTP_XOR_QUAD_CurrentVersionRun_08bf {
  strings:
    $key_08bf = { 5b d0 [2] 7f de [2] 54 f2 [2] 7a d0 [2] 6e cb [2] 61 d1 [2] 7f cc [2] 7d cd [2] 66 cb [2] 7a cc [2] 66 e3 }

  condition:
    any of them
}