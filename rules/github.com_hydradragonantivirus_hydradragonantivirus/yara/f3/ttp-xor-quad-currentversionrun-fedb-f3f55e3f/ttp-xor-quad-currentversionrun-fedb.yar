rule TTP_XOR_QUAD_CurrentVersionRun_fedb {
  strings:
    $key_fedb = { ad b4 [2] 89 ba [2] a2 96 [2] 8c b4 [2] 98 af [2] 97 b5 [2] 89 a8 [2] 8b a9 [2] 90 af [2] 8c a8 [2] 90 87 }

  condition:
    any of them
}