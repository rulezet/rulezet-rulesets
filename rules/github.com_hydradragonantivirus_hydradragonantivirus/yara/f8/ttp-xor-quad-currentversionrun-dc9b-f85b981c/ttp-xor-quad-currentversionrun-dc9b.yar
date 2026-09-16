rule TTP_XOR_QUAD_CurrentVersionRun_dc9b {
  strings:
    $key_dc9b = { 8f f4 [2] ab fa [2] 80 d6 [2] ae f4 [2] ba ef [2] b5 f5 [2] ab e8 [2] a9 e9 [2] b2 ef [2] ae e8 [2] b2 c7 }

  condition:
    any of them
}