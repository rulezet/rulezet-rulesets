rule TTP_XOR_QUAD_CurrentVersionRun_db83 {
  strings:
    $key_db83 = { 88 ec [2] ac e2 [2] 87 ce [2] a9 ec [2] bd f7 [2] b2 ed [2] ac f0 [2] ae f1 [2] b5 f7 [2] a9 f0 [2] b5 df }

  condition:
    any of them
}