rule TTP_XOR_QUAD_CurrentVersionRun_2683 {
  strings:
    $key_2683 = { 75 ec [2] 51 e2 [2] 7a ce [2] 54 ec [2] 40 f7 [2] 4f ed [2] 51 f0 [2] 53 f1 [2] 48 f7 [2] 54 f0 [2] 48 df }

  condition:
    any of them
}