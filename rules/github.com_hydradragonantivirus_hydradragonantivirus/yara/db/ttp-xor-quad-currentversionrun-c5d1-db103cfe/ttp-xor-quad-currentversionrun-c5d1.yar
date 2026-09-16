rule TTP_XOR_QUAD_CurrentVersionRun_c5d1 {
  strings:
    $key_c5d1 = { 96 be [2] b2 b0 [2] 99 9c [2] b7 be [2] a3 a5 [2] ac bf [2] b2 a2 [2] b0 a3 [2] ab a5 [2] b7 a2 [2] ab 8d }

  condition:
    any of them
}