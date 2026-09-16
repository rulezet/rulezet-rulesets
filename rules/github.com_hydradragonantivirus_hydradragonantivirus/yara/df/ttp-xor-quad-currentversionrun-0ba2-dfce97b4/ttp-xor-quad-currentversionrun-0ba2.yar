rule TTP_XOR_QUAD_CurrentVersionRun_0ba2 {
  strings:
    $key_0ba2 = { 58 cd [2] 7c c3 [2] 57 ef [2] 79 cd [2] 6d d6 [2] 62 cc [2] 7c d1 [2] 7e d0 [2] 65 d6 [2] 79 d1 [2] 65 fe }

  condition:
    any of them
}