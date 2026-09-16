rule TTP_XOR_QUAD_CurrentVersionRun_d61a {
  strings:
    $key_d61a = { 85 75 [2] a1 7b [2] 8a 57 [2] a4 75 [2] b0 6e [2] bf 74 [2] a1 69 [2] a3 68 [2] b8 6e [2] a4 69 [2] b8 46 }

  condition:
    any of them
}