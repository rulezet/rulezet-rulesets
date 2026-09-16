rule TTP_XOR_QUAD_CurrentVersionRun_cea2 {
  strings:
    $key_cea2 = { 9d cd [2] b9 c3 [2] 92 ef [2] bc cd [2] a8 d6 [2] a7 cc [2] b9 d1 [2] bb d0 [2] a0 d6 [2] bc d1 [2] a0 fe }

  condition:
    any of them
}