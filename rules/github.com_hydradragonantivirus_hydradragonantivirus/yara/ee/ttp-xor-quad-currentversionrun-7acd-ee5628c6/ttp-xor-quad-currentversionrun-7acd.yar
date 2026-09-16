rule TTP_XOR_QUAD_CurrentVersionRun_7acd {
  strings:
    $key_7acd = { 29 a2 [2] 0d ac [2] 26 80 [2] 08 a2 [2] 1c b9 [2] 13 a3 [2] 0d be [2] 0f bf [2] 14 b9 [2] 08 be [2] 14 91 }

  condition:
    any of them
}