rule TTP_XOR_QUAD_CurrentVersionRun_c383 {
  strings:
    $key_c383 = { 90 ec [2] b4 e2 [2] 9f ce [2] b1 ec [2] a5 f7 [2] aa ed [2] b4 f0 [2] b6 f1 [2] ad f7 [2] b1 f0 [2] ad df }

  condition:
    any of them
}