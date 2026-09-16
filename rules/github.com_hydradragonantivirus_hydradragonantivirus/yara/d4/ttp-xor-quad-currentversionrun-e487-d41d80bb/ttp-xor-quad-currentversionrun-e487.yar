rule TTP_XOR_QUAD_CurrentVersionRun_e487 {
  strings:
    $key_e487 = { b7 e8 [2] 93 e6 [2] b8 ca [2] 96 e8 [2] 82 f3 [2] 8d e9 [2] 93 f4 [2] 91 f5 [2] 8a f3 [2] 96 f4 [2] 8a db }

  condition:
    any of them
}