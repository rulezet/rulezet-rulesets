rule TTP_XOR_QUAD_CurrentVersionRun_4fd1 {
  strings:
    $key_4fd1 = { 1c be [2] 38 b0 [2] 13 9c [2] 3d be [2] 29 a5 [2] 26 bf [2] 38 a2 [2] 3a a3 [2] 21 a5 [2] 3d a2 [2] 21 8d }

  condition:
    any of them
}