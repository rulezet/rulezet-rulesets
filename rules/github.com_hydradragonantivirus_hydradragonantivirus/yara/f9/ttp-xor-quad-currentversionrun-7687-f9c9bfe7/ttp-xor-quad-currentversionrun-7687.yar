rule TTP_XOR_QUAD_CurrentVersionRun_7687 {
  strings:
    $key_7687 = { 25 e8 [2] 01 e6 [2] 2a ca [2] 04 e8 [2] 10 f3 [2] 1f e9 [2] 01 f4 [2] 03 f5 [2] 18 f3 [2] 04 f4 [2] 18 db }

  condition:
    any of them
}