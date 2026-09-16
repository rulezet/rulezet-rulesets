rule TTP_XOR_QUAD_CurrentVersionRun_1fcd {
  strings:
    $key_1fcd = { 4c a2 [2] 68 ac [2] 43 80 [2] 6d a2 [2] 79 b9 [2] 76 a3 [2] 68 be [2] 6a bf [2] 71 b9 [2] 6d be [2] 71 91 }

  condition:
    any of them
}