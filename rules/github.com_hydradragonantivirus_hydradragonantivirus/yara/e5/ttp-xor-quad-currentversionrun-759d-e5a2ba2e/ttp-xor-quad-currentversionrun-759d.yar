rule TTP_XOR_QUAD_CurrentVersionRun_759d {
  strings:
    $key_759d = { 26 f2 [2] 02 fc [2] 29 d0 [2] 07 f2 [2] 13 e9 [2] 1c f3 [2] 02 ee [2] 00 ef [2] 1b e9 [2] 07 ee [2] 1b c1 }

  condition:
    any of them
}