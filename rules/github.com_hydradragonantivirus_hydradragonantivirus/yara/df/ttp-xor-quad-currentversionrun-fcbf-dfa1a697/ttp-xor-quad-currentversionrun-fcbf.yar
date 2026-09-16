rule TTP_XOR_QUAD_CurrentVersionRun_fcbf {
  strings:
    $key_fcbf = { af d0 [2] 8b de [2] a0 f2 [2] 8e d0 [2] 9a cb [2] 95 d1 [2] 8b cc [2] 89 cd [2] 92 cb [2] 8e cc [2] 92 e3 }

  condition:
    any of them
}