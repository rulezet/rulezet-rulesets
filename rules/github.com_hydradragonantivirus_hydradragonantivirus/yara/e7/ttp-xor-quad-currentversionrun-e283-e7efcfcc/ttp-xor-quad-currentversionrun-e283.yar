rule TTP_XOR_QUAD_CurrentVersionRun_e283 {
  strings:
    $key_e283 = { b1 ec [2] 95 e2 [2] be ce [2] 90 ec [2] 84 f7 [2] 8b ed [2] 95 f0 [2] 97 f1 [2] 8c f7 [2] 90 f0 [2] 8c df }

  condition:
    any of them
}