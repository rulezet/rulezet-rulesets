rule TTP_XOR_QUAD_CurrentVersionRun_d0a8 {
  strings:
    $key_d0a8 = { 83 c7 [2] a7 c9 [2] 8c e5 [2] a2 c7 [2] b6 dc [2] b9 c6 [2] a7 db [2] a5 da [2] be dc [2] a2 db [2] be f4 }

  condition:
    any of them
}