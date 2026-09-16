rule TTP_XOR_QUAD_CurrentVersionRun_c1a2 {
  strings:
    $key_c1a2 = { 92 cd [2] b6 c3 [2] 9d ef [2] b3 cd [2] a7 d6 [2] a8 cc [2] b6 d1 [2] b4 d0 [2] af d6 [2] b3 d1 [2] af fe }

  condition:
    any of them
}