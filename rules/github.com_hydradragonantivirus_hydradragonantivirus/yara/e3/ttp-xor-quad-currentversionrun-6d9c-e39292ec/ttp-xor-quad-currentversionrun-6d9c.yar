rule TTP_XOR_QUAD_CurrentVersionRun_6d9c {
  strings:
    $key_6d9c = { 3e f3 [2] 1a fd [2] 31 d1 [2] 1f f3 [2] 0b e8 [2] 04 f2 [2] 1a ef [2] 18 ee [2] 03 e8 [2] 1f ef [2] 03 c0 }

  condition:
    any of them
}