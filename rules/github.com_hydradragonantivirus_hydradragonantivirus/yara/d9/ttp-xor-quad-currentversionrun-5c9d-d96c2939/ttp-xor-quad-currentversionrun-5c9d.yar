rule TTP_XOR_QUAD_CurrentVersionRun_5c9d {
  strings:
    $key_5c9d = { 0f f2 [2] 2b fc [2] 00 d0 [2] 2e f2 [2] 3a e9 [2] 35 f3 [2] 2b ee [2] 29 ef [2] 32 e9 [2] 2e ee [2] 32 c1 }

  condition:
    any of them
}