rule TTP_XOR_QUAD_CurrentVersionRun_6683 {
  strings:
    $key_6683 = { 35 ec [2] 11 e2 [2] 3a ce [2] 14 ec [2] 00 f7 [2] 0f ed [2] 11 f0 [2] 13 f1 [2] 08 f7 [2] 14 f0 [2] 08 df }

  condition:
    any of them
}