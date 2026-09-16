rule TTP_XOR_QUAD_CurrentVersionRun_7883 {
  strings:
    $key_7883 = { 2b ec [2] 0f e2 [2] 24 ce [2] 0a ec [2] 1e f7 [2] 11 ed [2] 0f f0 [2] 0d f1 [2] 16 f7 [2] 0a f0 [2] 16 df }

  condition:
    any of them
}