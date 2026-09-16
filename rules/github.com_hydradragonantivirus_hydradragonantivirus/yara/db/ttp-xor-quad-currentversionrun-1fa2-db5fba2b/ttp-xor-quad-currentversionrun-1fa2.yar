rule TTP_XOR_QUAD_CurrentVersionRun_1fa2 {
  strings:
    $key_1fa2 = { 4c cd [2] 68 c3 [2] 43 ef [2] 6d cd [2] 79 d6 [2] 76 cc [2] 68 d1 [2] 6a d0 [2] 71 d6 [2] 6d d1 [2] 71 fe }

  condition:
    any of them
}