rule TTP_XOR_QUAD_CurrentVersionRun_6c9d {
  strings:
    $key_6c9d = { 3f f2 [2] 1b fc [2] 30 d0 [2] 1e f2 [2] 0a e9 [2] 05 f3 [2] 1b ee [2] 19 ef [2] 02 e9 [2] 1e ee [2] 02 c1 }

  condition:
    any of them
}