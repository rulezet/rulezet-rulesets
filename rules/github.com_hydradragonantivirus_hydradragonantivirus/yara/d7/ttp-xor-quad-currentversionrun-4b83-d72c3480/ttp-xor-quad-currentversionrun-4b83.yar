rule TTP_XOR_QUAD_CurrentVersionRun_4b83 {
  strings:
    $key_4b83 = { 18 ec [2] 3c e2 [2] 17 ce [2] 39 ec [2] 2d f7 [2] 22 ed [2] 3c f0 [2] 3e f1 [2] 25 f7 [2] 39 f0 [2] 25 df }

  condition:
    any of them
}