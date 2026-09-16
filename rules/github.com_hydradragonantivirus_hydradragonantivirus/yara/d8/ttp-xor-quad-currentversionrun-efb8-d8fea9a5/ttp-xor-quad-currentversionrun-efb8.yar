rule TTP_XOR_QUAD_CurrentVersionRun_efb8 {
  strings:
    $key_efb8 = { bc d7 [2] 98 d9 [2] b3 f5 [2] 9d d7 [2] 89 cc [2] 86 d6 [2] 98 cb [2] 9a ca [2] 81 cc [2] 9d cb [2] 81 e4 }

  condition:
    any of them
}