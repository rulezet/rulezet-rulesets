rule TTP_XOR_QUAD_CurrentVersionRun_1683 {
  strings:
    $key_1683 = { 45 ec [2] 61 e2 [2] 4a ce [2] 64 ec [2] 70 f7 [2] 7f ed [2] 61 f0 [2] 63 f1 [2] 78 f7 [2] 64 f0 [2] 78 df }

  condition:
    any of them
}