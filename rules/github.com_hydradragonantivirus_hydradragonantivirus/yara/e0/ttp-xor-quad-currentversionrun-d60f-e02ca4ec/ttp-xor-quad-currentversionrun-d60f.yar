rule TTP_XOR_QUAD_CurrentVersionRun_d60f {
  strings:
    $key_d60f = { 85 60 [2] a1 6e [2] 8a 42 [2] a4 60 [2] b0 7b [2] bf 61 [2] a1 7c [2] a3 7d [2] b8 7b [2] a4 7c [2] b8 53 }

  condition:
    any of them
}