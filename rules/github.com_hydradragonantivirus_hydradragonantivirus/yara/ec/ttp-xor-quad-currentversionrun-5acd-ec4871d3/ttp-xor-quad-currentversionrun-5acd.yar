rule TTP_XOR_QUAD_CurrentVersionRun_5acd {
  strings:
    $key_5acd = { 09 a2 [2] 2d ac [2] 06 80 [2] 28 a2 [2] 3c b9 [2] 33 a3 [2] 2d be [2] 2f bf [2] 34 b9 [2] 28 be [2] 34 91 }

  condition:
    any of them
}