rule TTP_XOR_QUAD_CurrentVersionRun_1283 {
  strings:
    $key_1283 = { 41 ec [2] 65 e2 [2] 4e ce [2] 60 ec [2] 74 f7 [2] 7b ed [2] 65 f0 [2] 67 f1 [2] 7c f7 [2] 60 f0 [2] 7c df }

  condition:
    any of them
}