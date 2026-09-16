rule TTP_XOR_QUAD_CurrentVersionRun_e583 {
  strings:
    $key_e583 = { b6 ec [2] 92 e2 [2] b9 ce [2] 97 ec [2] 83 f7 [2] 8c ed [2] 92 f0 [2] 90 f1 [2] 8b f7 [2] 97 f0 [2] 8b df }

  condition:
    any of them
}