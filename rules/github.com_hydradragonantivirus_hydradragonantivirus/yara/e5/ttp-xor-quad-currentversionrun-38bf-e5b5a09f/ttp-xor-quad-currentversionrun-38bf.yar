rule TTP_XOR_QUAD_CurrentVersionRun_38bf {
  strings:
    $key_38bf = { 6b d0 [2] 4f de [2] 64 f2 [2] 4a d0 [2] 5e cb [2] 51 d1 [2] 4f cc [2] 4d cd [2] 56 cb [2] 4a cc [2] 56 e3 }

  condition:
    any of them
}