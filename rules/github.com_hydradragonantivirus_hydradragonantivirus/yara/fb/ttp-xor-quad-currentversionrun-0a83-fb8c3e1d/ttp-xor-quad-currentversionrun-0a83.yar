rule TTP_XOR_QUAD_CurrentVersionRun_0a83 {
  strings:
    $key_0a83 = { 59 ec [2] 7d e2 [2] 56 ce [2] 78 ec [2] 6c f7 [2] 63 ed [2] 7d f0 [2] 7f f1 [2] 64 f7 [2] 78 f0 [2] 64 df }

  condition:
    any of them
}