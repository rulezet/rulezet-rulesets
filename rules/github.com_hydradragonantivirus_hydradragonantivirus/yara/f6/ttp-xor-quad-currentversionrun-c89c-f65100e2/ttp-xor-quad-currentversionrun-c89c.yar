rule TTP_XOR_QUAD_CurrentVersionRun_c89c {
  strings:
    $key_c89c = { 9b f3 [2] bf fd [2] 94 d1 [2] ba f3 [2] ae e8 [2] a1 f2 [2] bf ef [2] bd ee [2] a6 e8 [2] ba ef [2] a6 c0 }

  condition:
    any of them
}