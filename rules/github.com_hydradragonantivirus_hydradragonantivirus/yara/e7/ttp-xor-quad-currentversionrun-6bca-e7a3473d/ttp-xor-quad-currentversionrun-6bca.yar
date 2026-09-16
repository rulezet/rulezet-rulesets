rule TTP_XOR_QUAD_CurrentVersionRun_6bca {
  strings:
    $key_6bca = { 38 a5 [2] 1c ab [2] 37 87 [2] 19 a5 [2] 0d be [2] 02 a4 [2] 1c b9 [2] 1e b8 [2] 05 be [2] 19 b9 [2] 05 96 }

  condition:
    any of them
}