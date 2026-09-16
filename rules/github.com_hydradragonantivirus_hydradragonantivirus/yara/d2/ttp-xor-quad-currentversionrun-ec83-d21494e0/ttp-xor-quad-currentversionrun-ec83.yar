rule TTP_XOR_QUAD_CurrentVersionRun_ec83 {
  strings:
    $key_ec83 = { bf ec [2] 9b e2 [2] b0 ce [2] 9e ec [2] 8a f7 [2] 85 ed [2] 9b f0 [2] 99 f1 [2] 82 f7 [2] 9e f0 [2] 82 df }

  condition:
    any of them
}