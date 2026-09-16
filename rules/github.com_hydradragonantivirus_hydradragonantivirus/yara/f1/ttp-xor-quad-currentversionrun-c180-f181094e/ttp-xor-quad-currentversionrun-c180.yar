rule TTP_XOR_QUAD_CurrentVersionRun_c180 {
  strings:
    $key_c180 = { 92 ef [2] b6 e1 [2] 9d cd [2] b3 ef [2] a7 f4 [2] a8 ee [2] b6 f3 [2] b4 f2 [2] af f4 [2] b3 f3 [2] af dc }

  condition:
    any of them
}