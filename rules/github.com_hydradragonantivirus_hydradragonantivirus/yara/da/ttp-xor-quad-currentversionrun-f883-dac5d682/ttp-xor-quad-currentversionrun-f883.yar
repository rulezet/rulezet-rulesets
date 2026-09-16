rule TTP_XOR_QUAD_CurrentVersionRun_f883 {
  strings:
    $key_f883 = { ab ec [2] 8f e2 [2] a4 ce [2] 8a ec [2] 9e f7 [2] 91 ed [2] 8f f0 [2] 8d f1 [2] 96 f7 [2] 8a f0 [2] 96 df }

  condition:
    any of them
}