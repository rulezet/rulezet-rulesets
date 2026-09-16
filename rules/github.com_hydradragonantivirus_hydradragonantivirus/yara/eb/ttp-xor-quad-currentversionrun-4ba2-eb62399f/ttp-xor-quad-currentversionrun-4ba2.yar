rule TTP_XOR_QUAD_CurrentVersionRun_4ba2 {
  strings:
    $key_4ba2 = { 18 cd [2] 3c c3 [2] 17 ef [2] 39 cd [2] 2d d6 [2] 22 cc [2] 3c d1 [2] 3e d0 [2] 25 d6 [2] 39 d1 [2] 25 fe }

  condition:
    any of them
}