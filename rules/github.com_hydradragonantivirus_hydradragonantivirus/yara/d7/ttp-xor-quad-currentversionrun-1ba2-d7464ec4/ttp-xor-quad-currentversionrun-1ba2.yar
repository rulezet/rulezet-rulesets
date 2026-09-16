rule TTP_XOR_QUAD_CurrentVersionRun_1ba2 {
  strings:
    $key_1ba2 = { 48 cd [2] 6c c3 [2] 47 ef [2] 69 cd [2] 7d d6 [2] 72 cc [2] 6c d1 [2] 6e d0 [2] 75 d6 [2] 69 d1 [2] 75 fe }

  condition:
    any of them
}