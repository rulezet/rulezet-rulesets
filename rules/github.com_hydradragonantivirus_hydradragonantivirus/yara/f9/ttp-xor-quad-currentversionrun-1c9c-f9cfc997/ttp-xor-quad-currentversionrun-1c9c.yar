rule TTP_XOR_QUAD_CurrentVersionRun_1c9c {
  strings:
    $key_1c9c = { 4f f3 [2] 6b fd [2] 40 d1 [2] 6e f3 [2] 7a e8 [2] 75 f2 [2] 6b ef [2] 69 ee [2] 72 e8 [2] 6e ef [2] 72 c0 }

  condition:
    any of them
}