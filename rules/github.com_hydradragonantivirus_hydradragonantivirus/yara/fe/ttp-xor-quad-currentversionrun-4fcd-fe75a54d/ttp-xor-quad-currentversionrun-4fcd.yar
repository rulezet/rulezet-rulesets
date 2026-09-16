rule TTP_XOR_QUAD_CurrentVersionRun_4fcd {
  strings:
    $key_4fcd = { 1c a2 [2] 38 ac [2] 13 80 [2] 3d a2 [2] 29 b9 [2] 26 a3 [2] 38 be [2] 3a bf [2] 21 b9 [2] 3d be [2] 21 91 }

  condition:
    any of them
}