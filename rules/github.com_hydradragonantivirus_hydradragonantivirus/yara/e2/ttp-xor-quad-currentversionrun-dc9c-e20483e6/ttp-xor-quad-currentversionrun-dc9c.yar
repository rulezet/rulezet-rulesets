rule TTP_XOR_QUAD_CurrentVersionRun_dc9c {
  strings:
    $key_dc9c = { 8f f3 [2] ab fd [2] 80 d1 [2] ae f3 [2] ba e8 [2] b5 f2 [2] ab ef [2] a9 ee [2] b2 e8 [2] ae ef [2] b2 c0 }

  condition:
    any of them
}