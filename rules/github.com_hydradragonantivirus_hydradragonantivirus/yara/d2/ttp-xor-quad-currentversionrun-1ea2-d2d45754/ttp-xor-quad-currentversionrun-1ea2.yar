rule TTP_XOR_QUAD_CurrentVersionRun_1ea2 {
  strings:
    $key_1ea2 = { 4d cd [2] 69 c3 [2] 42 ef [2] 6c cd [2] 78 d6 [2] 77 cc [2] 69 d1 [2] 6b d0 [2] 70 d6 [2] 6c d1 [2] 70 fe }

  condition:
    any of them
}