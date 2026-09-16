rule TTP_XOR_QUAD_CurrentVersionRun_ea83 {
  strings:
    $key_ea83 = { b9 ec [2] 9d e2 [2] b6 ce [2] 98 ec [2] 8c f7 [2] 83 ed [2] 9d f0 [2] 9f f1 [2] 84 f7 [2] 98 f0 [2] 84 df }

  condition:
    any of them
}