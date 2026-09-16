rule TTP_XOR_QUAD_CurrentVersionRun_0c9d {
  strings:
    $key_0c9d = { 5f f2 [2] 7b fc [2] 50 d0 [2] 7e f2 [2] 6a e9 [2] 65 f3 [2] 7b ee [2] 79 ef [2] 62 e9 [2] 7e ee [2] 62 c1 }

  condition:
    any of them
}