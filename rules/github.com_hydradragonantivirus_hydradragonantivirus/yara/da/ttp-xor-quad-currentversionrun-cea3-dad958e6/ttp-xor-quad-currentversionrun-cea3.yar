rule TTP_XOR_QUAD_CurrentVersionRun_cea3 {
  strings:
    $key_cea3 = { 9d cc [2] b9 c2 [2] 92 ee [2] bc cc [2] a8 d7 [2] a7 cd [2] b9 d0 [2] bb d1 [2] a0 d7 [2] bc d0 [2] a0 ff }

  condition:
    any of them
}