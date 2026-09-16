rule TTP_XOR_QUAD_CurrentVersionRun_6a83 {
  strings:
    $key_6a83 = { 39 ec [2] 1d e2 [2] 36 ce [2] 18 ec [2] 0c f7 [2] 03 ed [2] 1d f0 [2] 1f f1 [2] 04 f7 [2] 18 f0 [2] 04 df }

  condition:
    any of them
}