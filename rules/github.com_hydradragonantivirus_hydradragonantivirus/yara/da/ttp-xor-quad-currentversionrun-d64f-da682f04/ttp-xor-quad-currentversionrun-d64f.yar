rule TTP_XOR_QUAD_CurrentVersionRun_d64f {
  strings:
    $key_d64f = { 85 20 [2] a1 2e [2] 8a 02 [2] a4 20 [2] b0 3b [2] bf 21 [2] a1 3c [2] a3 3d [2] b8 3b [2] a4 3c [2] b8 13 }

  condition:
    any of them
}