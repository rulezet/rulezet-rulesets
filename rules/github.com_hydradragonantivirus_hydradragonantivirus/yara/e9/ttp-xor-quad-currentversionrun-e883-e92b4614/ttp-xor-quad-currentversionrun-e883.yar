rule TTP_XOR_QUAD_CurrentVersionRun_e883 {
  strings:
    $key_e883 = { bb ec [2] 9f e2 [2] b4 ce [2] 9a ec [2] 8e f7 [2] 81 ed [2] 9f f0 [2] 9d f1 [2] 86 f7 [2] 9a f0 [2] 86 df }

  condition:
    any of them
}