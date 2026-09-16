rule TTP_XOR_QUAD_CurrentVersionRun_5fa2 {
  strings:
    $key_5fa2 = { 0c cd [2] 28 c3 [2] 03 ef [2] 2d cd [2] 39 d6 [2] 36 cc [2] 28 d1 [2] 2a d0 [2] 31 d6 [2] 2d d1 [2] 31 fe }

  condition:
    any of them
}