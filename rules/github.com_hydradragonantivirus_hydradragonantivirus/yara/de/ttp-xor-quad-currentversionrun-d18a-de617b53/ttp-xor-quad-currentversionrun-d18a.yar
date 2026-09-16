rule TTP_XOR_QUAD_CurrentVersionRun_d18a {
  strings:
    $key_d18a = { 82 e5 [2] a6 eb [2] 8d c7 [2] a3 e5 [2] b7 fe [2] b8 e4 [2] a6 f9 [2] a4 f8 [2] bf fe [2] a3 f9 [2] bf d6 }

  condition:
    any of them
}