rule TTP_XOR_QUAD_CurrentVersionRun_3fd1 {
  strings:
    $key_3fd1 = { 6c be [2] 48 b0 [2] 63 9c [2] 4d be [2] 59 a5 [2] 56 bf [2] 48 a2 [2] 4a a3 [2] 51 a5 [2] 4d a2 [2] 51 8d }

  condition:
    any of them
}