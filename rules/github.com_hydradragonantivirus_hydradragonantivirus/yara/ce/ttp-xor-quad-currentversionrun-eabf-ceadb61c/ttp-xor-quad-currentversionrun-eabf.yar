rule TTP_XOR_QUAD_CurrentVersionRun_eabf {
  strings:
    $key_eabf = { b9 d0 [2] 9d de [2] b6 f2 [2] 98 d0 [2] 8c cb [2] 83 d1 [2] 9d cc [2] 9f cd [2] 84 cb [2] 98 cc [2] 84 e3 }

  condition:
    any of them
}