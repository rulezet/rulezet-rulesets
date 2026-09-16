rule TTP_XOR_QUAD_CurrentVersionRun_c283 {
  strings:
    $key_c283 = { 91 ec [2] b5 e2 [2] 9e ce [2] b0 ec [2] a4 f7 [2] ab ed [2] b5 f0 [2] b7 f1 [2] ac f7 [2] b0 f0 [2] ac df }

  condition:
    any of them
}