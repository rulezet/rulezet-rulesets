rule TTP_XOR_QUAD_CurrentVersionRun_d080 {
  strings:
    $key_d080 = { 83 ef [2] a7 e1 [2] 8c cd [2] a2 ef [2] b6 f4 [2] b9 ee [2] a7 f3 [2] a5 f2 [2] be f4 [2] a2 f3 [2] be dc }

  condition:
    any of them
}