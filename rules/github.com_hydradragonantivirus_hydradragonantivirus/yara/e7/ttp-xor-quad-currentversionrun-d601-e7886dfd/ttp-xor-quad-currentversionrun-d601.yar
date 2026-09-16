rule TTP_XOR_QUAD_CurrentVersionRun_d601 {
  strings:
    $key_d601 = { 85 6e [2] a1 60 [2] 8a 4c [2] a4 6e [2] b0 75 [2] bf 6f [2] a1 72 [2] a3 73 [2] b8 75 [2] a4 72 [2] b8 5d }

  condition:
    any of them
}