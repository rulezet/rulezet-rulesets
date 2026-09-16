rule TTP_XOR_QUAD_CurrentVersionRun_d60c {
  strings:
    $key_d60c = { 85 63 [2] a1 6d [2] 8a 41 [2] a4 63 [2] b0 78 [2] bf 62 [2] a1 7f [2] a3 7e [2] b8 78 [2] a4 7f [2] b8 50 }

  condition:
    any of them
}