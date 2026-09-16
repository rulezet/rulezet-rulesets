rule TTP_XOR_QUAD_CurrentVersionRun_2687 {
  strings:
    $key_2687 = { 75 e8 [2] 51 e6 [2] 7a ca [2] 54 e8 [2] 40 f3 [2] 4f e9 [2] 51 f4 [2] 53 f5 [2] 48 f3 [2] 54 f4 [2] 48 db }

  condition:
    any of them
}