rule TTP_XOR_QUAD_CurrentVersionRun_3387 {
  strings:
    $key_3387 = { 60 e8 [2] 44 e6 [2] 6f ca [2] 41 e8 [2] 55 f3 [2] 5a e9 [2] 44 f4 [2] 46 f5 [2] 5d f3 [2] 41 f4 [2] 5d db }

  condition:
    any of them
}