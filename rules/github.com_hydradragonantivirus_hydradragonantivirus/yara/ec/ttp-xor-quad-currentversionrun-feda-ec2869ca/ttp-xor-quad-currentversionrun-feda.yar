rule TTP_XOR_QUAD_CurrentVersionRun_feda {
  strings:
    $key_feda = { ad b5 [2] 89 bb [2] a2 97 [2] 8c b5 [2] 98 ae [2] 97 b4 [2] 89 a9 [2] 8b a8 [2] 90 ae [2] 8c a9 [2] 90 86 }

  condition:
    any of them
}